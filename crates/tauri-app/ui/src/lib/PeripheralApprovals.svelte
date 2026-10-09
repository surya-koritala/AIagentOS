<script>
  import { invoke } from '@tauri-apps/api/core';
  import { onMount, tick } from 'svelte';

  /** @type {Array<{request_id: string, agent_id: string, agent_name: string, tool_name: string, resource_identity: string, required_policy: string, status: string, grant_pending: boolean, active_uses: number}>} */
  let requests = [];
  /** @type {(typeof requests)[number] | null} */
  let selected = null;
  /** @type {HTMLDialogElement | undefined} */
  let approvalDialog;
  let connected = false;
  let refreshing = false;
  let deciding = false;
  let notice = '';

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      requests = await invoke('get_peripheral_requests');
      connected = true;
      if (selected && !requests.some(request => request.request_id === selected?.request_id && request.status === 'awaiting-approval')) {
        approvalDialog?.close();
        selected = null;
      }
    } catch {
      connected = false;
      approvalDialog?.close();
      selected = null;
    } finally { refreshing = false; }
  }

  async function review(request) {
    selected = request;
    notice = '';
    await tick();
    approvalDialog?.showModal();
  }

  function trapReviewFocus(event) {
    if (event.key !== 'Tab' || !approvalDialog) return;
    const controls = Array.from(approvalDialog.querySelectorAll('button')).filter(button => !button.disabled);
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (!first || !last) { event.preventDefault(); return; }
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first.focus();
    }
  }

  async function decide(command, requestId) {
    if (deciding || !connected) return;
    deciding = true;
    try {
      const result = await invoke(command, { requestId });
      notice = command === 'revoke_peripheral_request'
        ? `Pending grant revoked: ${result.pending_grant_revoked ? 'yes' : 'no'}; active uses cancelled: ${result.active_uses_cancelled}.`
        : command === 'approve_peripheral_request' ? 'One exact call approved.' : 'Request denied.';
      approvalDialog?.close();
      selected = null;
      await refresh();
    } catch {
      notice = 'The request changed or is unavailable. Refresh before deciding again.';
      await refresh();
    } finally { deciding = false; }
  }

  onMount(() => {
    refresh();
    const timer = setInterval(refresh, 1000);
    return () => clearInterval(timer);
  });
</script>

<section class="peripheral-approvals" aria-labelledby="peripheral-title">
  <div class="heading">
    <h2 id="peripheral-title">Peripheral approvals</h2>
    <button on:click={refresh} disabled={refreshing || deciding}>Refresh peripheral state</button>
  </div>
  <p class="summary">Local human approval authorizes one exact call. Revoke cancels every active use of that same contract.</p>
  <p role="status" aria-live="polite">{notice}</p>
  {#if !connected}
    <p>Local peripheral state is unavailable. Decisions require the embedded desktop kernel.</p>
  {:else if requests.length === 0}
    <p>No peripheral requests. Device backends are unavailable by default.</p>
  {:else}
    <p>Pending approval requests: {requests.filter(request => request.status === 'awaiting-approval').length}.</p>
    <ul aria-label="Peripheral request state">
      {#each requests as request (request.request_id)}
        <li>
          <strong>{request.agent_name}</strong> — {request.tool_name}
          <p>Resource identity: <code>{request.resource_identity}</code></p>
          <p>Status: {request.status}. Pending grants: {request.grant_pending ? 1 : 0}. Active uses: {request.active_uses}.</p>
          {#if request.active_uses > 0}<p class="in-use">In use</p>{/if}
          {#if request.status === 'awaiting-approval'}
            <button on:click={() => review(request)} disabled={deciding || !connected} aria-label={`Review peripheral request for ${request.agent_name}`}>Review request</button>
          {/if}
          {#if request.grant_pending || request.active_uses > 0}
            <button on:click={() => decide('revoke_peripheral_request', request.request_id)} disabled={deciding || !connected} aria-label={`Revoke peripheral access for ${request.agent_name}`}>Revoke</button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

{#if selected}
  <dialog bind:this={approvalDialog} aria-labelledby="peripheral-review-title" on:keydown={trapReviewFocus} on:close={() => { selected = null; }}>
    <h2 id="peripheral-review-title">Approve peripheral request</h2>
    <p>Agent: {selected.agent_name}</p>
    <p>Tool: {selected.tool_name}</p>
    <p>Resource identity: <code>{selected.resource_identity}</code></p>
    <p>Required human authority: {selected.required_policy}.</p>
    <p>Approval is single use. No device operation has started while this request waits.</p>
    <div class="actions">
      <button on:click={() => selected && decide('approve_peripheral_request', selected.request_id)} disabled={deciding || !connected}>Approve exact call</button>
      <button on:click={() => selected && decide('deny_peripheral_request', selected.request_id)} disabled={deciding || !connected}>Deny request</button>
      <button on:click={() => approvalDialog?.close()} disabled={deciding}>Close review</button>
    </div>
  </dialog>
{/if}

<style>
  .peripheral-approvals { margin: 1rem; padding: 1rem; border: 1px solid #46506b; border-radius: 8px; background: #171b2b; }
  .heading, .actions { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; justify-content: space-between; }
  h2 { margin: 0; font-size: 1.1rem; }
  p { margin: 0.65rem 0; }
  .summary { color: #c5cee3; }
  .in-use { font-weight: 700; color: #baf0c9; }
  ul { margin: 0; padding: 0; list-style: none; }
  li { border-top: 1px solid #46506b; padding: 0.75rem 0; }
  code { overflow-wrap: anywhere; }
  button { min-height: 44px; padding: 0.5rem 0.75rem; background: #233858; color: #f1f5ff; border: 1px solid #799ac6; border-radius: 6px; cursor: pointer; }
  button:disabled { opacity: 0.55; cursor: wait; }
  dialog { max-width: min(620px, calc(100vw - 2rem)); background: #171b2b; color: #f1f5ff; padding: 1.5rem; border: 2px solid #799ac6; border-radius: 8px; }
  dialog::backdrop { background: #0009; }
</style>

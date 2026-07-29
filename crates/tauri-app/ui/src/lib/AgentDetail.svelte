<script>
  import { invoke } from '@tauri-apps/api/core';
  import { createEventDispatcher } from 'svelte';

  export let agentId = null;
  export let agents = [];
  export let metrics = null;

  const dispatch = createEventDispatcher();
  let agent = null;
  let busy = false;
  let actionError = null;
  let checkpoints = [];
  let loadedCheckpointAgent = null;
  let checkpointsLoading = false;
  let checkpointStatus = '';
  let checkpointError = null;
  let pendingCheckpointDelete = null;
  let checkpointDeleteConfirmation = '';

  $: agent = agents.find(candidate => candidate.id === agentId) || null;
  $: if (agentId && agentId !== loadedCheckpointAgent && !checkpointsLoading) {
    loadedCheckpointAgent = agentId;
    loadCheckpoints(agentId);
  }

  async function runLifecycle(command, label) {
    if (!agentId || busy) return;
    busy = true;
    actionError = null;
    dispatch('operation', { label, active: true });
    try {
      await invoke(command, { agentId });
      dispatch('refresh');
    } catch (error) {
      actionError = String(error);
    } finally {
      busy = false;
      dispatch('operation', { label, active: false });
    }
  }

  async function loadCheckpoints(targetAgentId = agentId) {
    if (!targetAgentId || checkpointsLoading) return;
    checkpointsLoading = true;
    checkpointError = null;
    try {
      const loaded = await invoke('list_checkpoints', { agentId: targetAgentId });
      if (targetAgentId === agentId) checkpoints = loaded;
    } catch (error) {
      if (targetAgentId === agentId) checkpointError = String(error);
    } finally {
      checkpointsLoading = false;
    }
  }

  async function resumeCheckpoint(checkpointId) {
    if (!agentId || checkpointsLoading) return;
    const targetAgentId = agentId;
    checkpointsLoading = true;
    checkpointError = null;
    checkpointStatus = `Resuming checkpoint ${checkpointId}…`;
    dispatch('operation', { label: 'resuming checkpoint', active: true });
    try {
      const result = await invoke('resume_checkpoint', {
        agentId: targetAgentId,
        checkpointId,
      });
      checkpointStatus = `Checkpoint resumed; agent state is ${result.state}.`;
      dispatch('refresh');
      checkpointsLoading = false;
      await loadCheckpoints(targetAgentId);
    } catch (error) {
      checkpointError = String(error);
      checkpointStatus = '';
    } finally {
      checkpointsLoading = false;
      dispatch('operation', { label: 'resuming checkpoint', active: false });
    }
  }

  function requestCheckpointDelete(checkpointId) {
    pendingCheckpointDelete = { agentId, checkpointId };
    checkpointDeleteConfirmation = '';
    checkpointError = null;
    checkpointStatus = '';
  }

  function cancelCheckpointDelete() {
    pendingCheckpointDelete = null;
    checkpointDeleteConfirmation = '';
  }

  async function deleteCheckpoint() {
    if (
      !agentId ||
      !pendingCheckpointDelete ||
      checkpointDeleteConfirmation !== pendingCheckpointDelete.checkpointId ||
      checkpointsLoading
    ) return;
    const targetAgentId = pendingCheckpointDelete.agentId;
    const checkpointId = pendingCheckpointDelete.checkpointId;
    checkpointsLoading = true;
    checkpointError = null;
    checkpointStatus = `Deleting checkpoint ${checkpointId}…`;
    dispatch('operation', { label: 'deleting checkpoint', active: true });
    try {
      const existed = await invoke('delete_checkpoint', {
        agentId: targetAgentId,
        checkpointId,
        confirmCheckpointId: checkpointDeleteConfirmation,
      });
      checkpointStatus = existed
        ? `Checkpoint ${checkpointId} was deleted.`
        : `Checkpoint ${checkpointId} no longer existed.`;
      cancelCheckpointDelete();
      dispatch('refresh');
      checkpointsLoading = false;
      await loadCheckpoints(targetAgentId);
    } catch (error) {
      checkpointError = String(error);
      checkpointStatus = '';
    } finally {
      checkpointsLoading = false;
      dispatch('operation', { label: 'deleting checkpoint', active: false });
    }
  }
</script>

{#if agent}
<div class="detail-panel" aria-busy={busy || checkpointsLoading}>
  <div class="detail-header">
    <h2>{agent.name}</h2>
    <span class="state-badge" class:running={agent.state === 'Running'} class:paused={agent.state === 'Paused'}>
      {agent.state}
    </span>
  </div>

  <div class="actions">
    {#if agent.state === 'Running'}
      <button class="btn-warn" on:click={() => runLifecycle('pause_agent', 'pausing agent')} disabled={busy}><span aria-hidden="true">⏸</span> Pause</button>
      <button class="btn-danger" on:click={() => runLifecycle('stop_agent', 'stopping agent')} disabled={busy}><span aria-hidden="true">⏹</span> Stop</button>
    {:else if agent.state === 'Paused'}
      <button class="btn-primary" on:click={() => runLifecycle('resume_agent', 'resuming agent')} disabled={busy}><span aria-hidden="true">▶</span> Resume</button>
      <button class="btn-danger" on:click={() => runLifecycle('stop_agent', 'stopping agent')} disabled={busy}><span aria-hidden="true">⏹</span> Stop</button>
    {/if}
  </div>
  {#if busy}<p class="operation-status" role="status">Operation in progress…</p>{/if}
  {#if actionError}<p class="action-error" role="alert">{actionError}</p>{/if}

  <dl class="info-grid">
    <div class="info-card">
      <dt class="label">Priority</dt>
      <dd class="value">{agent.priority}</dd>
    </div>
    <div class="info-card">
      <dt class="label">Tokens used</dt>
      <dd class="value">{metrics ? metrics.tokens_consumed.toLocaleString() : 'Unavailable'}</dd>
    </div>
    <div class="info-card">
      <dt class="label">API calls</dt>
      <dd class="value">{metrics ? metrics.api_calls_made : 'Unavailable'}</dd>
    </div>
  </dl>

  <section class="checkpoint-section" aria-labelledby="checkpoint-heading">
    <div class="section-heading">
      <h3 id="checkpoint-heading">Generation checkpoints</h3>
      <button
        class="btn-secondary"
        on:click={() => loadCheckpoints()}
        disabled={checkpointsLoading}
      >Refresh</button>
    </div>
    {#if checkpointsLoading}
      <p class="operation-status" role="status">Loading checkpoint state…</p>
    {:else if checkpoints.length === 0}
      <p class="empty-state">No retained checkpoints for this agent.</p>
    {:else}
      <ul class="checkpoint-list">
        {#each checkpoints as checkpoint}
          <li>
            <code>{checkpoint.id}</code>
            <span>v{checkpoint.version} · {checkpoint.provider_id}/{checkpoint.model_id}</span>
            <span>Expires {checkpoint.expires_at}</span>
            <div class="checkpoint-actions">
              <button
                class="btn-primary"
                on:click={() => resumeCheckpoint(checkpoint.id)}
                disabled={checkpointsLoading}
              >Resume</button>
              <button
                class="btn-danger"
                on:click={() => requestCheckpointDelete(checkpoint.id)}
                disabled={checkpointsLoading}
              >Delete</button>
            </div>
          </li>
        {/each}
      </ul>
    {/if}

    {#if pendingCheckpointDelete}
      <div class="delete-confirmation" role="group" aria-labelledby="delete-checkpoint-heading">
        <h4 id="delete-checkpoint-heading">Confirm permanent checkpoint deletion</h4>
        <p>
          This removes checkpoint <code>{pendingCheckpointDelete.checkpointId}</code> from
          agent <code>{pendingCheckpointDelete.agentId}</code>. Type the exact checkpoint
          ID to continue.
        </p>
        <label for="checkpoint-delete-confirmation">Exact checkpoint ID</label>
        <input
          id="checkpoint-delete-confirmation"
          bind:value={checkpointDeleteConfirmation}
          autocomplete="off"
          spellcheck="false"
        />
        <div class="checkpoint-actions">
          <button
            class="btn-danger"
            on:click={deleteCheckpoint}
            disabled={checkpointDeleteConfirmation !== pendingCheckpointDelete.checkpointId || checkpointsLoading}
          >Permanently delete</button>
          <button class="btn-secondary" on:click={cancelCheckpointDelete}>Cancel</button>
        </div>
      </div>
    {/if}
    {#if checkpointStatus}<p class="operation-status" role="status">{checkpointStatus}</p>{/if}
    {#if checkpointError}<p class="action-error" role="alert">{checkpointError}</p>{/if}
  </section>
</div>
{/if}

<style>
  .detail-panel { padding: 1.5rem; }
  .detail-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
  h2 { margin: 0; font-size: 1.3rem; }
  .state-badge { font-size: 0.7rem; padding: 0.2rem 0.6rem; border-radius: 4px; background: #333; text-transform: uppercase; }
  .state-badge.running { background: #1a4a2e; color: #4ade80; }
  .state-badge.paused { background: #4a3a1a; color: #fbbf24; }
  .actions { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; }
  .actions button { min-height: 44px; padding: 0.4rem 1rem; border-radius: 8px; border: none; cursor: pointer; font-size: 0.8rem; }
  .actions button:disabled { opacity: 0.5; cursor: wait; }
  .operation-status { color: #93c5fd; font-size: 0.8rem; }
  .action-error { color: #fca5a5; font-size: 0.8rem; overflow-wrap: anywhere; }
  .btn-primary { background: #3276bd; color: white; }
  .btn-warn { background: #5c3c05; color: #fde68a; border: 1px solid #a16207 !important; }
  .btn-danger { background: #581717; color: #fecaca; border: 1px solid #991b1b !important; }
  .info-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; }
  .info-card { background: #1a1a2e; border: 1px solid #3f3f5a; border-radius: 10px; padding: 1rem; text-align: center; }
  .label { display: block; font-size: 0.7rem; color: #b9b9c8; text-transform: uppercase; }
  .value { display: block; margin: 0.25rem 0 0; font-size: 1.3rem; font-weight: 700; color: #8bc5ff; }
  .checkpoint-section { margin-top: 1.5rem; border-top: 1px solid #3f3f5a; padding-top: 1rem; }
  .section-heading { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
  .section-heading h3 { margin: 0; font-size: 0.95rem; }
  .checkpoint-list { list-style: none; margin: 0.75rem 0 0; padding: 0; display: grid; gap: 0.75rem; }
  .checkpoint-list li { display: grid; gap: 0.35rem; padding: 0.75rem; border: 1px solid #3f3f5a; border-radius: 8px; background: #161625; overflow-wrap: anywhere; }
  .checkpoint-list li > span { color: #b9b9c8; font-size: 0.75rem; }
  .checkpoint-actions { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }
  .checkpoint-actions button, .section-heading button { min-height: 40px; padding: 0.4rem 0.75rem; border-radius: 7px; cursor: pointer; }
  .checkpoint-actions button:disabled, .section-heading button:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-secondary { color: #e8e8f0; background: #29293f; border: 1px solid #5b5b76; }
  .delete-confirmation { margin-top: 1rem; padding: 0.9rem; border: 1px solid #b91c1c; border-radius: 8px; background: #2b1518; }
  .delete-confirmation h4 { margin: 0 0 0.5rem; }
  .delete-confirmation p { color: #fecaca; line-height: 1.4; overflow-wrap: anywhere; }
  .delete-confirmation label { display: block; margin-bottom: 0.35rem; font-weight: 700; }
  .delete-confirmation input { width: 100%; min-height: 44px; border: 1px solid #77778e; border-radius: 7px; background: #11111d; color: #f5f5fa; padding: 0.5rem 0.65rem; }
  .empty-state { color: #b9b9c8; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  @media (max-width: 700px) {
    .info-grid { grid-template-columns: 1fr; }
  }
</style>

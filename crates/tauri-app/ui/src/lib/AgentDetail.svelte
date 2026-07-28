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

  $: agent = agents.find(candidate => candidate.id === agentId) || null;

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
</script>

{#if agent}
<div class="detail-panel" aria-busy={busy}>
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
</style>

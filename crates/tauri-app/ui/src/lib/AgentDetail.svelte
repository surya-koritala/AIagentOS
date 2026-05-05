<script>
  import { invoke } from '@tauri-apps/api/core';
  import { createEventDispatcher } from 'svelte';

  export let agentId = null;

  const dispatch = createEventDispatcher();
  let agent = null;
  let activityLog = [];
  let metrics = null;

  $: if (agentId) loadAgentDetails();

  async function loadAgentDetails() {
    try {
      const agents = await invoke('list_agents');
      agent = agents.find(a => a.id === agentId);
      metrics = await invoke('get_metrics');
    } catch (e) {}
  }

  async function pauseAgent() {
    await invoke('pause_agent', { agentId });
    await loadAgentDetails();
  }

  async function resumeAgent() {
    await invoke('resume_agent', { agentId });
    await loadAgentDetails();
  }

  async function stopAgent() {
    await invoke('stop_agent', { agentId });
    await loadAgentDetails();
  }
</script>

{#if agent}
<div class="detail-panel">
  <div class="detail-header">
    <h2>{agent.name}</h2>
    <span class="state-badge" class:running={agent.state === 'Running'} class:paused={agent.state === 'Paused'}>
      {agent.state}
    </span>
  </div>

  <div class="actions">
    {#if agent.state === 'Running'}
      <button class="btn-warn" on:click={pauseAgent}>⏸ Pause</button>
      <button class="btn-danger" on:click={stopAgent}>⏹ Stop</button>
    {:else if agent.state === 'Paused'}
      <button class="btn-primary" on:click={resumeAgent}>▶ Resume</button>
      <button class="btn-danger" on:click={stopAgent}>⏹ Stop</button>
    {/if}
  </div>

  <div class="info-grid">
    <div class="info-card">
      <span class="label">Priority</span>
      <span class="value">{agent.priority}</span>
    </div>
    <div class="info-card">
      <span class="label">Tokens Used</span>
      <span class="value">{metrics?.tokens_consumed?.toLocaleString() || 0}</span>
    </div>
    <div class="info-card">
      <span class="label">API Calls</span>
      <span class="value">{metrics?.api_calls_made || 0}</span>
    </div>
  </div>
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
  .actions button { padding: 0.4rem 1rem; border-radius: 8px; border: none; cursor: pointer; font-size: 0.8rem; }
  .btn-primary { background: #4a90d9; color: white; }
  .btn-warn { background: #92600a; color: #fbbf24; }
  .btn-danger { background: #6b1a1a; color: #f87171; }
  .info-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; }
  .info-card { background: #1a1a2e; border: 1px solid #2a2a44; border-radius: 10px; padding: 1rem; text-align: center; }
  .label { display: block; font-size: 0.7rem; color: #666; text-transform: uppercase; }
  .value { display: block; font-size: 1.3rem; font-weight: 700; color: #4a90d9; margin-top: 0.25rem; }
</style>

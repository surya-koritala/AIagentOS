<script>
  import { createEventDispatcher } from 'svelte';

  export let agents = [];
  export let metrics = null;

  const dispatch = createEventDispatcher();
</script>

<div class="dashboard">
  <header>
    <h1>AI Agent OS</h1>
    <p class="subtitle">Your autonomous AI workforce</p>
  </header>

  <section aria-labelledby="summary-heading">
    <h2 class="visually-hidden" id="summary-heading">Operator summary</h2>
    <dl class="stats">
      <div class="stat-card">
        <dd class="stat-value">{agents.length}</dd>
        <dt class="stat-label">Agents</dt>
      </div>
      <div class="stat-card">
        <dd class="stat-value">{agents.filter(a => a.state === 'Running').length}</dd>
        <dt class="stat-label">Active</dt>
      </div>
      <div class="stat-card">
        <dd class="stat-value">{metrics ? metrics.tokens_consumed.toLocaleString() : 'Unavailable'}</dd>
        <dt class="stat-label">Tokens used</dt>
      </div>
      <div class="stat-card">
        <dd class="stat-value">{metrics ? metrics.api_calls_made : 'Unavailable'}</dd>
        <dt class="stat-label">API calls</dt>
      </div>
    </dl>
  </section>

  {#if agents.length === 0}
    <div class="empty-state">
      <div class="empty-icon" aria-hidden="true">🤖</div>
      <h2>No agents yet</h2>
      <p>Create your first agent using the sidebar to get started.</p>
    </div>
  {:else}
    <h2 class="section-title">Agents</h2>
    <div class="agent-grid">
      {#each agents as agent}
        <button class="agent-card" aria-label={`Open ${agent.name}, ${agent.state}`} on:click={() => dispatch('select', agent.id)}>
          <div class="agent-header">
            <span class="agent-name">{agent.name}</span>
            <span class="agent-state" class:running={agent.state === 'Running'} class:paused={agent.state === 'Paused'} class:stopped={agent.state === 'Stopped'}>
              {agent.state}
            </span>
          </div>
          <div class="agent-meta">Priority: {agent.priority}</div>
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .dashboard { padding: 2rem; overflow-y: auto; }
  header { margin-bottom: 2rem; }
  h1 { margin: 0; font-size: 2rem; background: linear-gradient(135deg, #4a90d9, #a855f7); background-clip: text; -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .subtitle { margin: 0.25rem 0 0; color: #b9b9c8; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: #1a1a2e; border: 1px solid #3f3f5a; border-radius: 12px; padding: 1.25rem; text-align: center; }
  .stat-value { display: block; margin: 0; font-size: 1.75rem; font-weight: 700; color: #8bc5ff; }
  .stat-label { display: block; font-size: 0.75rem; color: #b9b9c8; margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .empty-state { text-align: center; padding: 4rem 2rem; }
  .empty-icon { font-size: 4rem; margin-bottom: 1rem; }
  .empty-state h2 { color: #c7c7d2; }
  .empty-state p { color: #b9b9c8; }
  .section-title { font-size: 1rem; color: #b9b9c8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }
  .agent-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; }
  .agent-card { min-height: 72px; background: #1a1a2e; border: 1px solid #3f3f5a; border-radius: 12px; padding: 1rem; text-align: left; cursor: pointer; transition: border-color 0.2s; width: 100%; color: inherit; }
  .agent-card:hover { border-color: #8bc5ff; }
  .agent-header { display: flex; justify-content: space-between; align-items: center; }
  .agent-name { font-weight: 600; }
  .agent-state { font-size: 0.7rem; padding: 0.2rem 0.5rem; border-radius: 4px; background: #333; }
  .agent-state.running { background: #1a4a2e; color: #4ade80; }
  .agent-state.paused { background: #4a3a1a; color: #fbbf24; }
  .agent-state.stopped { background: #3a1a1a; color: #f87171; }
  .agent-meta { margin-top: 0.5rem; font-size: 0.8rem; color: #b9b9c8; }
  @media (max-width: 900px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
  }
  @media (max-width: 500px) {
    .dashboard { padding: 1rem; }
    .agent-grid { grid-template-columns: 1fr; }
  }
</style>

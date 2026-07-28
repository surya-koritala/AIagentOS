<script>
  export let agents = [];
</script>

<section class="agent-status" aria-labelledby="agent-status-heading">
  <h1 id="agent-status-heading">Agent status</h1>
  <p class="scope-note">
    Current state from the latest operator snapshot. This view is not an event history.
  </p>
  {#if agents.length === 0}
    <p class="empty">No agents are present in the current operator snapshot.</p>
  {:else}
    <ul class="status-list">
      {#each agents as agent}
        <li class="status-item">
          <span
            class="dot"
            aria-hidden="true"
            class:running={agent.state === 'Running'}
            class:paused={agent.state === 'Paused'}
            class:stopped={agent.state === 'Stopped'}
          ></span>
          <span class="agent-name">{agent.name}</span>
          <span class="state">{agent.state}</span>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .agent-status { padding: 1.5rem; overflow-y: auto; }
  h1 { margin: 0 0 0.5rem; font-size: 1.3rem; }
  .scope-note { max-width: 46rem; margin: 0 0 1.25rem; color: #b9b9c8; line-height: 1.5; }
  .empty { color: #b9b9c8; font-size: 0.85rem; }
  .status-list { display: flex; flex-direction: column; gap: 0.5rem; padding: 0; margin: 0; list-style: none; }
  .status-item { display: flex; align-items: center; gap: 0.75rem; min-height: 44px; padding: 0.6rem 0.75rem; background: #1a1a2e; border: 1px solid #3f3f5a; border-radius: 8px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .dot { background: #a7a7b8; }
  .dot.running { background: #4ade80; }
  .dot.paused { background: #fbbf24; }
  .dot.stopped { background: #f87171; }
  .agent-name { font-size: 0.85rem; font-weight: 500; }
  .state { margin-left: auto; font-size: 0.8rem; color: #b9b9c8; }
</style>

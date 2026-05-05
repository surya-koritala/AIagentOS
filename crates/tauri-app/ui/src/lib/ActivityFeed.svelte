<script>
  export let agents = [];

  // Simulated activity feed (in real app, would come from kernel events)
  let activities = [];

  $: {
    activities = agents.flatMap(a => [{
      agent: a.name,
      action: a.state === 'Running' ? 'Active' : a.state,
      time: 'now',
      type: a.state === 'Running' ? 'info' : a.state === 'Paused' ? 'warn' : 'error',
    }]);
  }
</script>

<div class="activity-feed">
  <h3>Activity Feed</h3>
  {#if activities.length === 0}
    <p class="empty">No activity yet. Create an agent to get started.</p>
  {:else}
    <div class="feed-list">
      {#each activities as activity}
        <div class="feed-item {activity.type}">
          <span class="dot"></span>
          <div class="feed-content">
            <span class="agent-name">{activity.agent}</span>
            <span class="action">{activity.action}</span>
          </div>
          <span class="time">{activity.time}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .activity-feed { padding: 1.5rem; }
  h3 { margin: 0 0 1rem; font-size: 0.85rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; }
  .empty { color: #555; font-size: 0.85rem; }
  .feed-list { display: flex; flex-direction: column; gap: 0.5rem; }
  .feed-item { display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 0.75rem; background: #1a1a2e; border: 1px solid #2a2a44; border-radius: 8px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .feed-item.info .dot { background: #4a90d9; }
  .feed-item.warn .dot { background: #fbbf24; }
  .feed-item.error .dot { background: #f87171; }
  .feed-content { flex: 1; }
  .agent-name { font-size: 0.85rem; font-weight: 500; }
  .action { font-size: 0.75rem; color: #888; margin-left: 0.5rem; }
  .time { font-size: 0.7rem; color: #555; }
</style>

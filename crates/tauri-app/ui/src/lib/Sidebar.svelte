<script>
  import { invoke } from '@tauri-apps/api/core';
  import { createEventDispatcher } from 'svelte';

  export let agents = [];
  export let activeAgentId = null;
  export let view = 'dashboard';

  const dispatch = createEventDispatcher();
  let newAgentName = '';
  let showNewAgent = false;

  async function createAgent() {
    if (!newAgentName.trim()) return;
    try {
      const id = await invoke('create_agent', { name: newAgentName.trim(), task: 'General assistant' });
      newAgentName = '';
      showNewAgent = false;
      dispatch('created', { id });
    } catch (e) {
      alert(`Failed: ${e}`);
    }
  }
</script>

<aside class="sidebar">
  <div class="logo">
    <span class="logo-icon">⚡</span>
    <span class="logo-text">Agent OS</span>
  </div>

  <nav>
    <button class="nav-item" class:active={view === 'dashboard'} on:click={() => dispatch('dashboard')}>
      <span>📊</span> Dashboard
    </button>
  </nav>

  <div class="section-header">
    <span>Agents</span>
    <button class="icon-btn" on:click={() => showNewAgent = !showNewAgent}>+</button>
  </div>

  {#if showNewAgent}
    <div class="new-agent-form">
      <input
        bind:value={newAgentName}
        placeholder="Agent name..."
        on:keydown={(e) => e.key === 'Enter' && createAgent()}
        autofocus
      />
      <button on:click={createAgent}>Create</button>
    </div>
  {/if}

  <div class="agent-list">
    {#each agents as agent}
      <button
        class="agent-item"
        class:active={agent.id === activeAgentId && view === 'chat'}
        on:click={() => dispatch('select', agent.id)}
      >
        <span class="dot" class:running={agent.state === 'Running'} class:paused={agent.state === 'Paused'}></span>
        <span class="name">{agent.name}</span>
      </button>
    {/each}
  </div>
</aside>

<style>
  .sidebar { width: 220px; background: #12121f; border-right: 1px solid #1e1e33; display: flex; flex-direction: column; }
  .logo { display: flex; align-items: center; gap: 0.5rem; padding: 1.25rem 1rem; border-bottom: 1px solid #1e1e33; }
  .logo-icon { font-size: 1.2rem; }
  .logo-text { font-weight: 700; font-size: 1rem; background: linear-gradient(135deg, #4a90d9, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  nav { padding: 0.75rem 0.5rem; }
  .nav-item { display: flex; align-items: center; gap: 0.5rem; width: 100%; padding: 0.5rem 0.75rem; border-radius: 8px; border: none; background: transparent; color: #999; cursor: pointer; font-size: 0.85rem; }
  .nav-item:hover { background: #1a1a2e; color: #ddd; }
  .nav-item.active { background: #1e2a44; color: #4a90d9; }
  .section-header { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 1rem; font-size: 0.7rem; color: #555; text-transform: uppercase; letter-spacing: 0.08em; }
  .icon-btn { background: none; border: 1px solid #333; color: #888; width: 20px; height: 20px; border-radius: 4px; cursor: pointer; font-size: 0.8rem; display: flex; align-items: center; justify-content: center; }
  .icon-btn:hover { border-color: #4a90d9; color: #4a90d9; }
  .new-agent-form { padding: 0 0.5rem; display: flex; gap: 0.25rem; margin-bottom: 0.5rem; }
  .new-agent-form input { flex: 1; padding: 0.35rem 0.5rem; border-radius: 6px; border: 1px solid #333; background: #1a1a2e; color: #eee; font-size: 0.8rem; }
  .new-agent-form button { padding: 0.35rem 0.6rem; border-radius: 6px; border: none; background: #4a90d9; color: white; cursor: pointer; font-size: 0.75rem; }
  .agent-list { flex: 1; overflow-y: auto; padding: 0 0.5rem; }
  .agent-item { display: flex; align-items: center; gap: 0.5rem; width: 100%; padding: 0.45rem 0.75rem; border-radius: 8px; border: none; background: transparent; color: #bbb; cursor: pointer; font-size: 0.82rem; text-align: left; }
  .agent-item:hover { background: #1a1a2e; }
  .agent-item.active { background: #1e2a44; color: #4a90d9; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #555; flex-shrink: 0; }
  .dot.running { background: #4ade80; }
  .dot.paused { background: #fbbf24; }
  .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>

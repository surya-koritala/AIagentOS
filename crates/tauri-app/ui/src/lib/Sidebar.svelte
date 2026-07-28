<script>
  import { invoke } from '@tauri-apps/api/core';
  import { createEventDispatcher, tick } from 'svelte';

  export let agents = [];
  export let activeAgentId = null;
  export let view = 'dashboard';

  const dispatch = createEventDispatcher();
  let newAgentName = '';
  let showNewAgent = false;
  let creating = false;
  let nameInput;

  async function toggleNewAgent() {
    showNewAgent = !showNewAgent;
    if (showNewAgent) {
      await tick();
      nameInput?.focus();
    }
  }

  async function createAgent() {
    if (!newAgentName.trim() || creating) return;
    const operation = 'creating agent';
    creating = true;
    dispatch('operation', { label: operation, active: true });
    try {
      const id = await invoke('create_agent', { name: newAgentName.trim(), task: 'General assistant' });
      newAgentName = '';
      showNewAgent = false;
      dispatch('created', { id });
    } catch (e) {
      alert(`Failed: ${e}`);
    } finally {
      creating = false;
      dispatch('operation', { label: operation, active: false });
    }
  }
</script>

<aside class="sidebar">
  <div class="logo">
    <span class="logo-icon" aria-hidden="true">⚡</span>
    <span class="logo-text">Agent OS</span>
  </div>

  <nav aria-label="Primary">
    <button class="nav-item" class:active={view === 'dashboard'} aria-current={view === 'dashboard' ? 'page' : undefined} on:click={() => dispatch('dashboard')}>
      <span aria-hidden="true">📊</span> Dashboard
    </button>
    <button class="nav-item" class:active={view === 'status'} aria-current={view === 'status' ? 'page' : undefined} on:click={() => dispatch('activity')}>
      <span aria-hidden="true">📡</span> Agent status
    </button>
    <button class="nav-item" class:active={view === 'settings'} aria-current={view === 'settings' ? 'page' : undefined} on:click={() => dispatch('settings')}>
      <span aria-hidden="true">⚙️</span> Settings
    </button>
  </nav>

  <div class="section-header">
    <h2 id="agents-heading">Agents</h2>
    <button
      class="icon-btn"
      aria-label={showNewAgent ? 'Cancel creating an agent' : 'Create a new agent'}
      aria-expanded={showNewAgent}
      aria-controls="new-agent-form"
      on:click={toggleNewAgent}
    >+</button>
  </div>

  {#if showNewAgent}
    <div class="new-agent-form" id="new-agent-form">
      <label class="visually-hidden" for="new-agent-name">Agent name</label>
      <input
        id="new-agent-name"
        bind:this={nameInput}
        bind:value={newAgentName}
        placeholder="Agent name"
        on:keydown={(e) => e.key === 'Enter' && createAgent()}
      />
      <button on:click={createAgent} disabled={creating}>{creating ? 'Creating…' : 'Create'}</button>
    </div>
  {/if}

  <ul class="agent-list" aria-labelledby="agents-heading">
    {#each agents as agent}
      <li>
        <button
          class="agent-item"
          class:active={agent.id === activeAgentId && view === 'chat'}
          aria-current={agent.id === activeAgentId && view === 'chat' ? 'true' : undefined}
          aria-label={`${agent.name}, ${agent.state}`}
          on:click={() => dispatch('select', agent.id)}
        >
          <span class="dot" aria-hidden="true" class:running={agent.state === 'Running'} class:paused={agent.state === 'Paused'}></span>
          <span class="name">{agent.name}</span>
        </button>
      </li>
    {/each}
    {#if agents.length === 0}
      <li class="empty-agents">No agents</li>
    {/if}
  </ul>
</aside>

<style>
  .sidebar { width: 220px; background: #12121f; border-right: 1px solid #1e1e33; display: flex; flex-direction: column; }
  .logo { display: flex; align-items: center; gap: 0.5rem; padding: 1.25rem 1rem; border-bottom: 1px solid #1e1e33; }
  .logo-icon { font-size: 1.2rem; }
  .logo-text { font-weight: 700; font-size: 1rem; background: linear-gradient(135deg, #4a90d9, #a855f7); background-clip: text; -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  nav { padding: 0.75rem 0.5rem; }
  .nav-item { display: flex; align-items: center; gap: 0.5rem; width: 100%; min-height: 44px; padding: 0.5rem 0.75rem; border-radius: 8px; border: none; background: transparent; color: #b9b9c8; cursor: pointer; font-size: 0.85rem; }
  .nav-item:hover { background: #1a1a2e; color: #ddd; }
  .nav-item.active { background: #1e2a44; color: #9dccff; }
  .section-header { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0.75rem 0.5rem 1rem; color: #a7a7b8; text-transform: uppercase; letter-spacing: 0.08em; }
  .section-header h2 { margin: 0; font-size: 0.7rem; font-weight: 600; }
  .icon-btn { background: none; border: 1px solid #66667a; color: #d0d0db; min-width: 32px; min-height: 32px; border-radius: 6px; cursor: pointer; font-size: 1rem; display: flex; align-items: center; justify-content: center; }
  .icon-btn:hover { border-color: #8bc5ff; color: #8bc5ff; }
  .new-agent-form { padding: 0 0.5rem; display: flex; gap: 0.25rem; margin-bottom: 0.5rem; }
  .new-agent-form input { min-width: 0; flex: 1; min-height: 36px; padding: 0.35rem 0.5rem; border-radius: 6px; border: 1px solid #66667a; background: #1a1a2e; color: #eee; font-size: 0.8rem; }
  .new-agent-form button { min-height: 36px; padding: 0.35rem 0.6rem; border-radius: 6px; border: none; background: #3276bd; color: white; cursor: pointer; font-size: 0.75rem; }
  .agent-list { flex: 1; overflow-y: auto; padding: 0 0.5rem; margin: 0; list-style: none; }
  .agent-item { display: flex; align-items: center; gap: 0.5rem; width: 100%; min-height: 40px; padding: 0.45rem 0.75rem; border-radius: 8px; border: none; background: transparent; color: #c7c7d2; cursor: pointer; font-size: 0.82rem; text-align: left; }
  .agent-item:hover { background: #1a1a2e; }
  .agent-item.active { background: #1e2a44; color: #9dccff; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #555; flex-shrink: 0; }
  .dot.running { background: #4ade80; }
  .dot.paused { background: #fbbf24; }
  .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .empty-agents { margin: 0.5rem 0.75rem; color: #a7a7b8; font-size: 0.8rem; }
  @media (max-width: 700px) {
    .sidebar { width: 100%; border-right: 0; border-bottom: 1px solid #1e1e33; }
    nav { display: grid; grid-template-columns: repeat(3, 1fr); }
    .nav-item { justify-content: center; padding-inline: 0.35rem; }
    .agent-list { max-height: 9rem; }
  }
</style>

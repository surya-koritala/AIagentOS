<script>
  import { invoke } from '@tauri-apps/api/core';
  import ChatPanel from './lib/ChatPanel.svelte';
  import Sidebar from './lib/Sidebar.svelte';
  import SetupModal from './lib/SetupModal.svelte';
  import Dashboard from './lib/Dashboard.svelte';

  let showSetup = false;
  let agents = [];
  let activeAgentId = null;
  let view = 'dashboard'; // 'dashboard' | 'chat'
  let metrics = { tokens_consumed: 0, api_calls_made: 0, time_elapsed_ms: 0 };

  async function init() {
    try {
      const config = await invoke('load_config');
      if (!config.setup_complete) { showSetup = true; return; }
      await refreshAgents();
      await refreshMetrics();
    } catch (e) {
      showSetup = true;
    }
  }

  async function refreshAgents() {
    agents = await invoke('list_agents');
  }

  async function refreshMetrics() {
    metrics = await invoke('get_metrics');
  }

  async function onAgentCreated(event) {
    activeAgentId = event.detail.id;
    view = 'chat';
    await refreshAgents();
  }

  function onSelectAgent(event) {
    activeAgentId = event.detail;
    view = 'chat';
  }

  async function onSetupComplete() {
    showSetup = false;
    await refreshAgents();
  }

  init();
</script>

<main>
  {#if showSetup}
    <SetupModal on:complete={onSetupComplete} />
  {:else}
    <div class="app-layout">
      <Sidebar
        {agents}
        {activeAgentId}
        {view}
        on:select={onSelectAgent}
        on:created={onAgentCreated}
        on:dashboard={() => { view = 'dashboard'; activeAgentId = null; }}
      />
      <div class="content">
        {#if view === 'dashboard'}
          <Dashboard {agents} {metrics} on:select={onSelectAgent} />
        {:else}
          <ChatPanel agentId={activeAgentId} on:messageSent={refreshMetrics} />
        {/if}
      </div>
    </div>
  {/if}
</main>

<style>
  :global(*) { box-sizing: border-box; }
  :global(body) {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f0f1a;
    color: #e8e8f0;
    font-size: 14px;
  }
  :global(::selection) { background: #4a90d9; color: white; }
  main { height: 100vh; display: flex; }
  .app-layout { display: flex; width: 100%; height: 100%; }
  .content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
</style>

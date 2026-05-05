<script>
  import { invoke } from '@tauri-apps/api/core';
  import ChatPanel from './lib/ChatPanel.svelte';
  import Sidebar from './lib/Sidebar.svelte';
  import SetupModal from './lib/SetupModal.svelte';
  import Dashboard from './lib/Dashboard.svelte';
  import AgentDetail from './lib/AgentDetail.svelte';
  import Settings from './lib/Settings.svelte';
  import ActivityFeed from './lib/ActivityFeed.svelte';

  let showSetup = false;
  let agents = [];
  let activeAgentId = null;
  let view = 'dashboard'; // 'dashboard' | 'chat' | 'settings' | 'activity'
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

  async function refreshAgents() { agents = await invoke('list_agents'); }
  async function refreshMetrics() { metrics = await invoke('get_metrics'); }

  function onAgentCreated(event) { activeAgentId = event.detail.id; view = 'chat'; refreshAgents(); }
  function onSelectAgent(event) { activeAgentId = event.detail; view = 'chat'; }
  async function onSetupComplete() { showSetup = false; await refreshAgents(); }

  init();
</script>

<main>
  {#if showSetup}
    <SetupModal on:complete={onSetupComplete} />
  {:else}
    <div class="app-layout">
      <Sidebar
        {agents} {activeAgentId} {view}
        on:select={onSelectAgent}
        on:created={onAgentCreated}
        on:dashboard={() => { view = 'dashboard'; activeAgentId = null; }}
        on:settings={() => { view = 'settings'; }}
        on:activity={() => { view = 'activity'; }}
      />
      <div class="content">
        {#if view === 'dashboard'}
          <Dashboard {agents} {metrics} on:select={onSelectAgent} />
        {:else if view === 'chat'}
          <ChatPanel agentId={activeAgentId} on:messageSent={refreshMetrics} />
        {:else if view === 'settings'}
          <Settings />
        {:else if view === 'activity'}
          <ActivityFeed {agents} />
        {/if}
      </div>
      {#if view === 'chat' && activeAgentId}
        <div class="detail-sidebar">
          <AgentDetail agentId={activeAgentId} />
        </div>
      {/if}
    </div>
  {/if}
</main>

<style>
  :global(*) { box-sizing: border-box; }
  :global(body) { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f1a; color: #e8e8f0; font-size: 14px; }
  :global(::selection) { background: #4a90d9; color: white; }
  main { height: 100vh; display: flex; }
  .app-layout { display: flex; width: 100%; height: 100%; }
  .content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .detail-sidebar { width: 280px; border-left: 1px solid #1e1e33; overflow-y: auto; }
</style>

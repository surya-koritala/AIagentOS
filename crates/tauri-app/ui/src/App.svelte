<script>
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import ChatPanel from './lib/ChatPanel.svelte';
  import Sidebar from './lib/Sidebar.svelte';
  import SetupModal from './lib/SetupModal.svelte';
  import Dashboard from './lib/Dashboard.svelte';
  import AgentDetail from './lib/AgentDetail.svelte';
  import Settings from './lib/Settings.svelte';
  import ActivityFeed from './lib/ActivityFeed.svelte';
  import {
    applyOperatorView,
    beginOperation,
    beginRefresh,
    createOperatorState,
    failRefresh,
    finishOperation,
    statusMessage,
  } from './lib/operatorState.js';

  let showSetup = false;
  let activeAgentId = null;
  let view = 'dashboard'; // 'dashboard' | 'chat' | 'settings' | 'activity'
  let operatorState = createOperatorState();
  let agents = [];
  let metrics = null;
  $: agents = operatorState.agents;
  $: metrics = operatorState.metrics;

  async function init() {
    // Wait for Tauri IPC to be ready
    if (!window.__TAURI_INTERNALS__) {
      await new Promise(r => setTimeout(r, 500));
    }
    try {
      const config = await invoke('load_config');
      if (!config.setup_complete) { showSetup = true; return; }
      await refreshOperator();
    } catch (e) {
      showSetup = true;
    }
  }

  async function refreshOperator() {
    if (showSetup || operatorState.refreshing) return;
    operatorState = beginRefresh(operatorState);
    try {
      const operatorView = await invoke('get_operator_view');
      operatorState = applyOperatorView(operatorState, operatorView);
    } catch (error) {
      operatorState = failRefresh(operatorState, error);
    }
  }

  function onOperation(event) {
    const { label, active } = event.detail;
    operatorState = active
      ? beginOperation(operatorState, label)
      : finishOperation(operatorState, label);
  }

  function onAgentCreated(event) { activeAgentId = event.detail.id; view = 'chat'; refreshOperator(); }
  function onSelectAgent(event) { activeAgentId = event.detail; view = 'chat'; }
  async function onSetupComplete() { showSetup = false; await refreshOperator(); }

  onMount(() => {
    init();
    const refreshTimer = setInterval(refreshOperator, 10_000);
    return () => clearInterval(refreshTimer);
  });
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
        on:operation={onOperation}
        on:dashboard={() => { view = 'dashboard'; activeAgentId = null; }}
        on:settings={() => { view = 'settings'; }}
        on:activity={() => { view = 'activity'; }}
      />
      <div class="content">
        <div
          class="status-banner"
          class:stale={operatorState.phase === 'stale'}
          class:partial={operatorState.phase === 'partial'}
          class:working={operatorState.refreshing || operatorState.operation}
          class:reconnected={operatorState.reconnected}
          role="status"
          aria-live="polite"
        >
          <span>{statusMessage(operatorState)}</span>
          {#if operatorState.phase === 'stale' || operatorState.phase === 'partial'}
            <button on:click={refreshOperator} disabled={operatorState.refreshing}>Retry now</button>
          {/if}
        </div>
        {#if view === 'dashboard'}
          <Dashboard {agents} {metrics} on:select={onSelectAgent} />
        {:else if view === 'chat'}
          <ChatPanel
            agentId={activeAgentId}
            on:messageSent={refreshOperator}
            on:operation={onOperation}
          />
        {:else if view === 'settings'}
          <Settings />
        {:else if view === 'activity'}
          <ActivityFeed {agents} />
        {/if}
      </div>
      {#if view === 'chat' && activeAgentId}
        <div class="detail-sidebar">
          <AgentDetail
            agentId={activeAgentId}
            {agents}
            {metrics}
            on:refresh={refreshOperator}
            on:operation={onOperation}
          />
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
  .status-banner { min-height: 38px; padding: 0.55rem 1rem; display: flex; align-items: center; justify-content: space-between; gap: 1rem; background: #142b20; border-bottom: 1px solid #245b3d; color: #9ce7b7; }
  .status-banner.stale { background: #341a1a; border-color: #6b2a2a; color: #fca5a5; }
  .status-banner.partial { background: #352a12; border-color: #6b531c; color: #fde68a; }
  .status-banner.working { background: #172b46; border-color: #28568a; color: #bfdbfe; }
  .status-banner.reconnected { background: #172f2b; border-color: #297566; color: #99f6e4; }
  .status-banner button { border: 1px solid currentColor; border-radius: 6px; background: transparent; color: inherit; padding: 0.3rem 0.65rem; cursor: pointer; }
  .status-banner button:disabled { opacity: 0.5; cursor: wait; }
</style>

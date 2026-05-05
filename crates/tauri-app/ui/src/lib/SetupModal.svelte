<script>
  import { invoke } from '@tauri-apps/api/core';
  import { createEventDispatcher } from 'svelte';

  const dispatch = createEventDispatcher();

  let step = 1;
  let provider = 'azure-openai';
  let apiKey = '';
  let azureEndpoint = '';
  let azureDeployment = 'gpt-4o';
  let testing = false;
  let testResult = null;

  async function testAndSave() {
    testing = true;
    testResult = null;
    try {
      await invoke('save_config', {
        llmProvider: provider,
        apiKey,
        defaultModel: provider === 'azure-openai' ? azureDeployment : null,
      });
      testResult = 'success';
      step = 2;
    } catch (e) {
      testResult = `Failed: ${e}`;
    }
    testing = false;
  }

  function complete() {
    dispatch('complete');
  }
</script>

<div class="modal-overlay">
  <div class="modal">
    {#if step === 1}
      <div class="step-indicator">Step 1 of 2</div>
      <h1>Welcome to AI Agent OS</h1>
      <p>Connect your LLM provider to get started.</p>

      <label>
        Provider
        <select bind:value={provider}>
          <option value="azure-openai">Azure OpenAI (recommended)</option>
          <option value="openai">OpenAI</option>
          <option value="anthropic">Anthropic</option>
          <option value="local">Local (Ollama)</option>
        </select>
      </label>

      {#if provider === 'azure-openai'}
        <label>
          Azure Endpoint
          <input bind:value={azureEndpoint} placeholder="https://your-resource.openai.azure.com" />
        </label>
        <label>
          Deployment Name
          <input bind:value={azureDeployment} placeholder="gpt-4o" />
        </label>
        <label>
          API Key
          <input bind:value={apiKey} type="password" placeholder="Your Azure OpenAI API key" />
        </label>
      {:else if provider === 'local'}
        <label>
          Ollama URL
          <input bind:value={apiKey} placeholder="http://localhost:11434" />
        </label>
      {:else}
        <label>
          API Key
          <input bind:value={apiKey} type="password" placeholder="sk-..." />
        </label>
      {/if}

      {#if testResult && testResult !== 'success'}
        <div class="result error">{testResult}</div>
      {/if}

      <button class="primary" on:click={testAndSave} disabled={testing || !apiKey.trim()}>
        {testing ? 'Connecting...' : 'Connect & Continue →'}
      </button>

    {:else}
      <div class="step-indicator">Step 2 of 2</div>
      <div class="success-icon">✓</div>
      <h1>You're all set!</h1>
      <p>Your {provider === 'azure-openai' ? 'Azure OpenAI' : provider} connection is configured. Create an agent to start working.</p>
      <button class="primary" on:click={complete}>Launch Dashboard →</button>
    {/if}
  </div>
</div>

<style>
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
  .modal { background: #16162a; border: 1px solid #2a2a44; border-radius: 20px; padding: 2.5rem; width: 440px; max-width: 90vw; }
  .step-indicator { font-size: 0.75rem; color: #4a90d9; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1rem; }
  h1 { margin: 0 0 0.5rem; font-size: 1.5rem; }
  p { color: #777; margin: 0 0 1.5rem; line-height: 1.5; }
  label { display: block; margin-bottom: 1rem; font-size: 0.8rem; color: #999; }
  select, input { display: block; width: 100%; margin-top: 0.3rem; padding: 0.6rem 0.75rem; border-radius: 8px; border: 1px solid #333; background: #1a1a2e; color: #eee; font-size: 0.9rem; }
  select:focus, input:focus { outline: none; border-color: #4a90d9; }
  .primary { width: 100%; padding: 0.75rem; border-radius: 10px; border: none; background: linear-gradient(135deg, #4a90d9, #6366f1); color: white; font-weight: 600; font-size: 0.95rem; cursor: pointer; margin-top: 0.5rem; }
  .primary:hover { opacity: 0.9; }
  .primary:disabled { opacity: 0.4; cursor: not-allowed; }
  .result.error { margin-top: 0.5rem; padding: 0.6rem; border-radius: 8px; font-size: 0.8rem; background: #2a1a1a; color: #f87171; border: 1px solid #3a2020; }
  .success-icon { font-size: 3rem; color: #4ade80; text-align: center; margin-bottom: 1rem; background: #1a3a2e; width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1.5rem; }
</style>

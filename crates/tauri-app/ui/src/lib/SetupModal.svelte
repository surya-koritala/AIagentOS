<script>
  import { invoke } from '@tauri-apps/api/core';
  import { createEventDispatcher, onMount, tick } from 'svelte';

  const dispatch = createEventDispatcher();

  let step = 1;
  let provider = 'azure-openai';
  let configuredProviders = [];
  let credentialStoreAvailable = true;
  let providerCredential = '';
  let azureEndpoint = '';
  let azureDeployment = 'gpt-4o';
  let localEndpoint = 'http://localhost:11434';
  let testing = false;
  let testResult = null;
  let modal;
  let firstControl;

  function focusableControls() {
    if (!modal) return [];
    return Array.from(modal.querySelectorAll(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    ));
  }

  function trapFocus(event) {
    if (event.key !== 'Tab') return;
    const controls = focusableControls();
    if (controls.length === 0) return;
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  async function loadSettings() {
    try {
      const config = await invoke('load_config');
      configuredProviders = config.configured_providers || [];
      credentialStoreAvailable = config.credential_store_available !== false;
      provider = config.llm_provider || provider;
      azureEndpoint = config.azure_endpoint || '';
      azureDeployment = config.azure_deployment || azureDeployment;
      localEndpoint = config.local_endpoint || localEndpoint;
    } catch (e) {}
  }

  async function testAndSave() {
    testing = true;
    testResult = null;
    const submittedCredential = providerCredential;
    providerCredential = '';
    try {
      await invoke('save_config', {
        llmProvider: provider,
        providerCredential: submittedCredential || null,
        defaultModel: provider === 'azure-openai' ? azureDeployment : null,
        azureEndpoint,
        azureDeployment,
        localEndpoint,
      });
      testResult = 'success';
      step = 2;
      await tick();
      firstControl?.focus();
    } catch (e) {
      testResult = `Failed: ${e}`;
    }
    testing = false;
  }

  function complete() {
    dispatch('complete');
  }

  loadSettings();

  onMount(async () => {
    await tick();
    firstControl?.focus();
  });
</script>

<div class="modal-overlay">
  <div
    class="modal"
    bind:this={modal}
    role="dialog"
    tabindex="-1"
    aria-modal="true"
    aria-labelledby="setup-title"
    aria-describedby="setup-description"
    aria-busy={testing}
    on:keydown={trapFocus}
  >
    {#if step === 1}
      <div class="step-indicator">Step 1 of 2</div>
      <h1 id="setup-title">Welcome to AI Agent OS</h1>
      <p id="setup-description">Connect your LLM provider to get started.</p>

      <label>
        Provider
        <select bind:this={firstControl} bind:value={provider}>
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
      {:else if provider === 'local'}
        <label>
          Ollama URL
          <input bind:value={localEndpoint} placeholder="http://localhost:11434" />
        </label>
      {/if}

      {#if provider !== 'local'}
        <label>
          Provider credential
          <input
            type="password"
            bind:value={providerCredential}
            autocomplete="new-password"
            placeholder={configuredProviders.includes(provider) ? 'Leave blank to keep the current source' : 'Enter a credential'}
            disabled={!credentialStoreAvailable}
          />
        </label>
        <p class="credential-note">
          Provider secrets are sent only to the native app and are never returned to this screen.
          {#if configuredProviders.includes(provider)}
            A credential source is already configured; leave the field blank to keep it.
          {:else if !credentialStoreAvailable}
            The platform credential store is unavailable. Set {provider === 'azure-openai' ? 'AZURE_OPENAI_API_KEY' : provider === 'openai' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY'} before starting the app.
          {:else}
            The credential will be stored by the operating system, not in the AgentOS config file.
          {/if}
        </p>
      {/if}

      {#if testResult && testResult !== 'success'}
        <div class="result error" role="alert">{testResult}</div>
      {/if}

      <button
        class="primary"
        on:click={testAndSave}
        disabled={testing || (provider !== 'local' && !configuredProviders.includes(provider) && !providerCredential.trim())}
      >
        {testing ? 'Saving...' : 'Save & Continue →'}
      </button>

    {:else}
      <div class="step-indicator">Step 2 of 2</div>
      <div class="success-icon" aria-hidden="true">✓</div>
      <h1 id="setup-title">You're all set!</h1>
      <p id="setup-description">Your {provider === 'azure-openai' ? 'Azure OpenAI' : provider} connection is configured. Create an agent to start working.</p>
      <button class="primary" bind:this={firstControl} on:click={complete}>Launch Dashboard →</button>
    {/if}
  </div>
</div>

<style>
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
  .modal { background: #16162a; border: 1px solid #4a4a68; border-radius: 20px; padding: 2.5rem; width: 440px; max-width: 90vw; max-height: 90vh; overflow-y: auto; }
  .step-indicator { font-size: 0.75rem; color: #8bc5ff; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1rem; }
  h1 { margin: 0 0 0.5rem; font-size: 1.5rem; }
  p { color: #b9b9c8; margin: 0 0 1.5rem; line-height: 1.5; }
  label { display: block; margin-bottom: 1rem; font-size: 0.8rem; color: #c7c7d2; }
  select, input { display: block; width: 100%; min-height: 44px; margin-top: 0.3rem; padding: 0.6rem 0.75rem; border-radius: 8px; border: 1px solid #66667a; background: #1a1a2e; color: #eee; font-size: 0.9rem; }
  select:focus, input:focus { border-color: #8bc5ff; }
  .primary { width: 100%; min-height: 44px; padding: 0.75rem; border-radius: 10px; border: none; background: linear-gradient(135deg, #3276bd, #4f46c7); color: white; font-weight: 600; font-size: 0.95rem; cursor: pointer; margin-top: 0.5rem; }
  .primary:hover { opacity: 0.9; }
  .primary:disabled { opacity: 0.4; cursor: not-allowed; }
  .result.error { margin-top: 0.5rem; padding: 0.6rem; border-radius: 8px; font-size: 0.8rem; background: #2a1a1a; color: #fca5a5; border: 1px solid #7f1d1d; }
  .credential-note { font-size: 0.8rem; color: #c7c7d2; margin-bottom: 1rem; }
  .success-icon { font-size: 3rem; color: #4ade80; text-align: center; margin-bottom: 1rem; background: #1a3a2e; width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1.5rem; }
</style>

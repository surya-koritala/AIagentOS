<script>
  import { invoke } from '@tauri-apps/api/core';
  import { createEventDispatcher } from 'svelte';

  const dispatch = createEventDispatcher();

  let config = {};
  let provider = 'azure-openai';
  let apiKey = '';
  let azureEndpoint = '';
  let azureDeployment = 'gpt-4o';
  let saving = false;
  let message = '';

  async function loadSettings() {
    try {
      config = await invoke('load_config');
      provider = config.llm_provider || 'azure-openai';
      apiKey = config.api_keys?.[provider] || '';
      azureEndpoint = config.azure_endpoint || '';
      azureDeployment = config.azure_deployment || 'gpt-4o';
    } catch (e) {}
  }

  async function save() {
    saving = true;
    message = '';
    try {
      await invoke('save_config', { llmProvider: provider, apiKey, defaultModel: azureDeployment });
      message = '✓ Saved successfully';
    } catch (e) {
      message = `✗ Error: ${e}`;
    }
    saving = false;
  }

  loadSettings();
</script>

<div class="settings">
  <h2>Settings</h2>

  <section>
    <h3>LLM Provider</h3>
    <label>
      Provider
      <select bind:value={provider}>
        <option value="azure-openai">Azure OpenAI</option>
        <option value="openai">OpenAI</option>
        <option value="anthropic">Anthropic</option>
        <option value="local">Local (Ollama)</option>
      </select>
    </label>

    {#if provider === 'azure-openai'}
      <label>Endpoint <input bind:value={azureEndpoint} placeholder="https://your-resource.openai.azure.com" /></label>
      <label>Deployment <input bind:value={azureDeployment} placeholder="gpt-4o" /></label>
    {/if}

    <label>
      {provider === 'local' ? 'URL' : 'API Key'}
      {#if provider === 'local'}
        <input bind:value={apiKey} placeholder="http://localhost:11434" />
      {:else}
        <input bind:value={apiKey} type="password" placeholder="sk-..." />
      {/if}
    </label>

    {#if message}
      <div class="message" class:success={message.startsWith('✓')}>{message}</div>
    {/if}

    <button on:click={save} disabled={saving}>{saving ? 'Saving...' : 'Save Settings'}</button>
  </section>

  <section>
    <h3>Data</h3>
    <p class="hint">Database: {config.data_dir || '~/.local/share/ai-agent-os'}/agent_os.db</p>
    <p class="hint">Config: ~/.config/ai-agent-os/config.toml</p>
  </section>
</div>

<style>
  .settings { padding: 2rem; max-width: 600px; overflow-y: auto; }
  h2 { margin: 0 0 1.5rem; font-size: 1.3rem; }
  h3 { font-size: 0.85rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin: 1.5rem 0 0.75rem; }
  section { background: #1a1a2e; border: 1px solid #2a2a44; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; }
  label { display: block; margin-bottom: 0.75rem; font-size: 0.8rem; color: #999; }
  select, input { display: block; width: 100%; margin-top: 0.25rem; padding: 0.5rem 0.75rem; border-radius: 8px; border: 1px solid #333; background: #12121f; color: #eee; font-size: 0.85rem; box-sizing: border-box; }
  button { width: 100%; padding: 0.6rem; border-radius: 8px; border: none; background: #4a90d9; color: white; font-weight: 600; cursor: pointer; margin-top: 0.5rem; }
  button:disabled { opacity: 0.5; }
  .message { margin-top: 0.5rem; font-size: 0.8rem; color: #f87171; }
  .message.success { color: #4ade80; }
  .hint { font-size: 0.75rem; color: #555; margin: 0.25rem 0; }
</style>

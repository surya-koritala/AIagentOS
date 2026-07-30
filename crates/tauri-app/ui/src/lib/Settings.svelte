<script>
  import { invoke } from '@tauri-apps/api/core';

  let config = {};
  let provider = 'azure-openai';
  let configuredProviders = [];
  let credentialStoreAvailable = true;
  let providerCredential = '';
  let azureEndpoint = '';
  let azureDeployment = 'gpt-4o';
  let localEndpoint = 'http://localhost:11434';
  let saving = false;
  let message = '';
  let availableUpdate = null;
  let checkingUpdate = false;
  let confirmingUpdate = false;
  let installingUpdate = false;
  let updateMessage = '';
  let updateError = false;

  async function loadSettings() {
    try {
      config = await invoke('load_config');
      provider = config.llm_provider || 'azure-openai';
      configuredProviders = config.configured_providers || [];
      credentialStoreAvailable = config.credential_store_available !== false;
      azureEndpoint = config.azure_endpoint || '';
      azureDeployment = config.azure_deployment || 'gpt-4o';
      localEndpoint = config.local_endpoint || 'http://localhost:11434';
    } catch (e) {}
  }

  async function save() {
    saving = true;
    message = '';
    const submittedCredential = providerCredential;
    providerCredential = '';
    try {
      await invoke('save_config', {
        llmProvider: provider,
        providerCredential: submittedCredential || null,
        defaultModel: azureDeployment,
        azureEndpoint,
        azureDeployment,
        localEndpoint,
      });
      message = '✓ Saved successfully';
      await loadSettings();
    } catch (e) {
      message = `✗ Error: ${e}`;
    }
    saving = false;
  }

  async function removeStoredCredential() {
    saving = true;
    message = '';
    providerCredential = '';
    try {
      const removed = await invoke('delete_provider_credential', { provider });
      message = removed
        ? '✓ Stored credential removed'
        : '✓ No stored credential was present';
      await loadSettings();
    } catch (e) {
      message = `✗ Error: ${e}`;
    }
    saving = false;
  }

  async function checkForUpdate() {
    if (checkingUpdate || installingUpdate) return;
    checkingUpdate = true;
    confirmingUpdate = false;
    updateMessage = '';
    updateError = false;
    try {
      availableUpdate = await invoke('check_for_update');
      updateMessage = availableUpdate
        ? `Signed update ${availableUpdate.version} is available. Review it before installing.`
        : 'This installation is up to date.';
    } catch (e) {
      availableUpdate = null;
      updateError = true;
      updateMessage = `Update check failed: ${e}`;
    }
    checkingUpdate = false;
  }

  async function installUpdate() {
    if (!availableUpdate || installingUpdate) return;
    const expectedVersion = availableUpdate.version;
    installingUpdate = true;
    confirmingUpdate = false;
    updateError = false;
    updateMessage = `Verifying and installing signed update ${expectedVersion}…`;
    try {
      await invoke('install_update', { expectedVersion });
      updateMessage = `Signed update ${expectedVersion} installed. Restarting…`;
    } catch (e) {
      updateError = true;
      updateMessage = `Update ${expectedVersion} was not installed: ${e}`;
      installingUpdate = false;
    }
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

    {#if provider === 'local'}
      <label>Ollama URL <input bind:value={localEndpoint} placeholder="http://localhost:11434" /></label>
    {:else}
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
      <p class="credential-status">
        Credentials are sent only to the native app and are never returned to this screen.
        {#if configuredProviders.includes(provider)}
          The selected provider is configured. Enter a new value to rotate its stored credential.
        {:else if !credentialStoreAvailable}
          The platform credential store is unavailable. Set {provider === 'azure-openai' ? 'AZURE_OPENAI_API_KEY' : provider === 'openai' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY'} before starting the app.
        {:else}
          The credential will be stored by the operating system, not in the AgentOS config file.
        {/if}
      </p>
      {#if configuredProviders.includes(provider) && credentialStoreAvailable}
        <button class="secondary" on:click={removeStoredCredential} disabled={saving}>
          Remove stored credential
        </button>
      {/if}
    {/if}

    {#if message}
      <div
        class="message"
        class:success={message.startsWith('✓')}
        role={message.startsWith('✓') ? 'status' : 'alert'}
      >{message}</div>
    {/if}

    <button on:click={save} disabled={saving || (provider !== 'local' && !configuredProviders.includes(provider) && !providerCredential.trim())}>
      {saving ? 'Saving...' : 'Save Settings'}
    </button>
  </section>

  <section>
    <h3>Data</h3>
    <p class="hint">Database: {config.data_dir || '~/.local/share/ai-agent-os'}/agent_os.db</p>
    <p class="hint">Config: ~/.config/ai-agent-os/config.toml</p>
  </section>

  <section aria-labelledby="software-update-heading">
    <h3 id="software-update-heading">Software update</h3>
    <p class="hint">
      Updates are downloaded over HTTPS and must match the updater signature built into this app.
    </p>
    <button class="secondary neutral" on:click={checkForUpdate} disabled={checkingUpdate || installingUpdate}>
      {checkingUpdate ? 'Checking for updates…' : 'Check for updates'}
    </button>

    {#if availableUpdate}
      <div class="update-card">
        <dl>
          <div><dt>Installed</dt><dd>{availableUpdate.current_version}</dd></div>
          <div><dt>Available</dt><dd>{availableUpdate.version}</dd></div>
          <div><dt>Target</dt><dd>{availableUpdate.target}</dd></div>
        </dl>
        {#if availableUpdate.published_at}
          <p class="hint">Published {availableUpdate.published_at}</p>
        {/if}
        {#if availableUpdate.notes}
          <p class="update-notes">{availableUpdate.notes}</p>
        {/if}
        {#if !confirmingUpdate}
          <button on:click={() => { confirmingUpdate = true; }}>
            Review install {availableUpdate.version}
          </button>
        {:else}
          <div class="update-confirmation" aria-labelledby="update-confirmation-heading">
            <h4 id="update-confirmation-heading">Confirm update {availableUpdate.version}</h4>
            <p>
              This replaces the installed desktop application and restarts it.
              Keep the current version available for operator-led rollback.
              Automatic downgrade is not available.
            </p>
            <div class="confirmation-actions">
              <button class="secondary neutral" on:click={() => { confirmingUpdate = false; }} disabled={installingUpdate}>
                Cancel
              </button>
              <button on:click={installUpdate} disabled={installingUpdate}>
                {installingUpdate ? 'Installing…' : `Confirm install ${availableUpdate.version}`}
              </button>
            </div>
          </div>
        {/if}
      </div>
    {/if}

    {#if updateMessage}
      <div class="message" class:success={!updateError} role={updateError ? 'alert' : 'status'}>
        {updateMessage}
      </div>
    {/if}
  </section>
</div>

<style>
  .settings { padding: 2rem; max-width: 600px; overflow-y: auto; }
  h2 { margin: 0 0 1.5rem; font-size: 1.3rem; }
  h3 { font-size: 0.85rem; color: #b9b9c8; text-transform: uppercase; letter-spacing: 0.05em; margin: 1.5rem 0 0.75rem; }
  section { background: #1a1a2e; border: 1px solid #3f3f5a; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; }
  label { display: block; margin-bottom: 0.75rem; font-size: 0.8rem; color: #c7c7d2; }
  select, input { display: block; width: 100%; min-height: 44px; margin-top: 0.25rem; padding: 0.5rem 0.75rem; border-radius: 8px; border: 1px solid #66667a; background: #12121f; color: #eee; font-size: 0.85rem; box-sizing: border-box; }
  button { width: 100%; min-height: 44px; padding: 0.6rem; border-radius: 8px; border: none; background: #3276bd; color: white; font-weight: 600; cursor: pointer; margin-top: 0.5rem; }
  button:disabled { opacity: 0.5; }
  button.secondary { background: transparent; color: #fca5a5; border: 1px solid #7f1d1d; margin-bottom: 0.5rem; }
  button.secondary.neutral { color: #d8d8e3; border-color: #66667a; }
  .message { margin-top: 0.5rem; font-size: 0.8rem; color: #f87171; }
  .message.success { color: #86efac; }
  .hint { font-size: 0.75rem; color: #b9b9c8; margin: 0.25rem 0; }
  .credential-status { font-size: 0.8rem; color: #c7c7d2; line-height: 1.5; }
  .update-card { margin-top: 0.75rem; padding: 0.85rem; border: 1px solid #4a4a68; border-radius: 8px; background: #12121f; }
  .update-card dl { display: grid; gap: 0.35rem; margin: 0 0 0.75rem; }
  .update-card dl div { display: flex; justify-content: space-between; gap: 1rem; }
  .update-card dt { color: #b9b9c8; }
  .update-card dd { margin: 0; overflow-wrap: anywhere; }
  .update-notes { max-height: 10rem; overflow-y: auto; white-space: pre-wrap; color: #c7c7d2; line-height: 1.5; }
  .update-confirmation { margin-top: 0.75rem; padding: 0.75rem; border: 1px solid #7c5c18; border-radius: 8px; background: #352a12; }
  .update-confirmation h4 { margin: 0 0 0.4rem; color: #fde68a; }
  .update-confirmation p { margin: 0; color: #f5deb0; line-height: 1.45; }
  .confirmation-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-top: 0.5rem; }
  .confirmation-actions button { margin: 0; }
</style>

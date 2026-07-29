<script>
  import { invoke } from '@tauri-apps/api/core';
  import { createEventDispatcher } from 'svelte';

  export let state;

  const dispatch = createEventDispatcher();
  let serviceBusy = null;
  let serviceError = '';
  let serviceStatus = '';
  let pendingServiceControl = null;
  let serviceConfirmation = '';
  let serviceHistory = [];
  let historyTarget = null;
  let historyLoading = false;
  let tunableBusy = null;
  let tunableError = '';
  let tunableStatus = '';
  let pendingTunableControl = null;
  let tunableInput = '';
  let tunableAudit = [];
  let tunableAuditTarget = null;
  let tunableAuditLoading = false;

  const availability = provider => {
    if (provider.probe_timed_out) return 'Probe timed out';
    if (provider.circuit_open) return 'Circuit open';
    return provider.available ? 'Available' : 'Unavailable';
  };

  const serviceOperationLabel = target => {
    const verb = target.action === 'start'
      ? 'starting'
      : target.action === 'stop'
        ? 'stopping'
        : 'restarting';
    return `${verb} service ${target.name}`;
  };

  function requestServiceControl(action, service) {
    const target = {
      action,
      name: service.name,
      state: service.state,
      agentId: service.agent_id,
    };
    serviceError = '';
    serviceStatus = '';
    if (action === 'start') {
      executeServiceControl(target);
      return;
    }
    pendingServiceControl = target;
    serviceConfirmation = '';
  }

  function cancelServiceControl() {
    pendingServiceControl = null;
    serviceConfirmation = '';
  }

  async function executeServiceControl(target = pendingServiceControl) {
    if (
      !target ||
      serviceBusy ||
      (target.action !== 'start' && serviceConfirmation !== target.name)
    ) return;
    const frozenTarget = { ...target };
    serviceBusy = frozenTarget.name;
    serviceError = '';
    serviceStatus = `${frozenTarget.action === 'start' ? 'Starting' : frozenTarget.action === 'stop' ? 'Stopping' : 'Restarting'} service ${frozenTarget.name}…`;
    dispatch('operation', {
      label: serviceOperationLabel(frozenTarget),
      active: true,
    });
    try {
      const args = { serviceName: frozenTarget.name };
      if (frozenTarget.action !== 'start') {
        args.confirmServiceName = serviceConfirmation;
      }
      const updated = await invoke(`${frozenTarget.action}_service`, args);
      serviceStatus = `Service ${updated.name} is ${updated.state}.`;
      cancelServiceControl();
      dispatch('refresh');
      if (historyTarget === frozenTarget.name) {
        await loadServiceHistory(frozenTarget.name);
      }
    } catch (error) {
      serviceError = String(error);
      serviceStatus = '';
    } finally {
      serviceBusy = null;
      dispatch('operation', {
        label: serviceOperationLabel(frozenTarget),
        active: false,
      });
    }
  }

  async function loadServiceHistory(serviceName) {
    if (!serviceName || historyLoading) return;
    const frozenName = serviceName;
    historyTarget = frozenName;
    historyLoading = true;
    serviceError = '';
    try {
      const entries = await invoke('service_history', {
        serviceName: frozenName,
        limit: 50,
      });
      if (historyTarget === frozenName) serviceHistory = entries;
    } catch (error) {
      if (historyTarget === frozenName) {
        serviceHistory = [];
        serviceError = String(error);
      }
    } finally {
      historyLoading = false;
    }
  }

  function requestTunableControl(action, tunable) {
    pendingTunableControl = {
      action,
      name: tunable.name,
      value: tunable.value,
      revision: tunable.revision,
      minimum: tunable.minimum,
      maximum: tunable.maximum,
      persisted: tunable.persisted,
    };
    tunableInput = action === 'set' ? String(tunable.value) : '';
    tunableError = '';
    tunableStatus = '';
  }

  function cancelTunableControl() {
    pendingTunableControl = null;
    tunableInput = '';
  }

  function parseTunableValue(value) {
    if (!/^(0|[1-9]\d*)$/.test(value)) return null;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }

  function parsedRollbackTarget(target, input) {
    if (!target || target.action !== 'rollback') return null;
    const parts = input.split('|');
    if (parts.length !== 2 || parts[1] !== target.name) return null;
    const revision = parseTunableValue(parts[0]);
    if (
      revision === null ||
      revision < 1 ||
      revision >= target.revision
    ) return null;
    return revision;
  }

  function canSubmitTunableControl(target, input, busy) {
    if (!target || busy) return false;
    if (target.action === 'rollback') {
      return parsedRollbackTarget(target, input) !== null;
    }
    const value = parseTunableValue(input);
    return (
      value !== null &&
      value >= target.minimum &&
      value <= target.maximum
    );
  }

  async function executeTunableControl() {
    if (!canSubmitTunableControl(pendingTunableControl, tunableInput, tunableBusy)) return;
    const frozenTarget = { ...pendingTunableControl };
    const value = frozenTarget.action === 'set'
      ? parseTunableValue(tunableInput)
      : null;
    const targetRevision = frozenTarget.action === 'rollback'
      ? parsedRollbackTarget(frozenTarget, tunableInput)
      : null;
    tunableBusy = frozenTarget.name;
    tunableError = '';
    tunableStatus = `${frozenTarget.action === 'set' ? 'Updating' : 'Rolling back'} ${frozenTarget.name}…`;
    dispatch('operation', {
      label: `${frozenTarget.action === 'set' ? 'updating' : 'rolling back'} tunable ${frozenTarget.name}`,
      active: true,
    });
    try {
      const updated = frozenTarget.action === 'set'
        ? await invoke('set_operator_tunable', {
            tunableName: frozenTarget.name,
            value,
            expectedRevision: frozenTarget.revision,
          })
        : await invoke('rollback_operator_tunable', {
            tunableName: frozenTarget.name,
            targetRevision,
            expectedRevision: frozenTarget.revision,
            confirmTunableName: frozenTarget.name,
          });
      tunableStatus = `${updated.name} is ${updated.value} at revision ${updated.revision}.`;
      cancelTunableControl();
      dispatch('refresh');
      if (tunableAuditTarget === frozenTarget.name) {
        await loadTunableAudit(frozenTarget.name);
      }
    } catch (error) {
      tunableError = String(error);
      tunableStatus = '';
    } finally {
      tunableBusy = null;
      dispatch('operation', {
        label: `${frozenTarget.action === 'set' ? 'updating' : 'rolling back'} tunable ${frozenTarget.name}`,
        active: false,
      });
    }
  }

  async function loadTunableAudit(tunableName) {
    if (!tunableName || tunableAuditLoading) return;
    const frozenName = tunableName;
    tunableAuditTarget = frozenName;
    tunableAuditLoading = true;
    tunableError = '';
    try {
      const entries = await invoke('operator_tunable_audit', {
        tunableName: frozenName,
        limit: 50,
      });
      if (tunableAuditTarget === frozenName) tunableAudit = entries;
    } catch (error) {
      if (tunableAuditTarget === frozenName) {
        tunableAudit = [];
        tunableError = String(error);
      }
    } finally {
      tunableAuditLoading = false;
    }
  }
</script>

<section class="operations" aria-labelledby="operations-heading">
  <header>
    <h1 id="operations-heading">Operations</h1>
    <p>
      Atomic {state.scope}-scope snapshot from {state.kernelVersion}
      (protocol {state.protocolVersion}, {state.consistency} consistency).
      This view is not an event history.
    </p>
  </header>

  <dl class="summary">
    <div>
      <dt>Agents</dt>
      <dd>{state.agents.length} / {state.totalVisibleAgents}</dd>
    </div>
    <div>
      <dt>Providers available</dt>
      <dd>{state.providers.filter(provider => provider.available && !provider.circuit_open).length} / {state.providers.length}</dd>
    </div>
    <div>
      <dt>Gate decisions</dt>
      <dd>{state.scopedGate.allowed} allowed · {state.scopedGate.denied} denied</dd>
    </div>
    <div>
      <dt>Loaded packages</dt>
      <dd>{state.packages.length}</dd>
    </div>
  </dl>

  <section aria-labelledby="agent-enforcement-heading">
    <h2 id="agent-enforcement-heading">Agent enforcement</h2>
    {#if state.agents.length === 0}
      <p class="empty">No agents are present in this caller scope.</p>
    {:else}
      <ul class="agent-grid">
        {#each state.agents as agent}
          <li>
            <div class="title-row">
              <span class="dot" aria-hidden="true" class:running={agent.state === 'Running'} class:paused={agent.state === 'Paused'} class:stopped={agent.state === 'Stopped'}></span>
              <strong>{agent.name}</strong>
              <span class="pill">{agent.state}</span>
            </div>
            <dl class="details">
              <div><dt>Scheduler</dt><dd>{agent.scheduler_state}</dd></div>
              <div><dt>Sandbox</dt><dd>{agent.sandbox_active ? 'Active' : 'Inactive'}</dd></div>
              <div><dt>Priority</dt><dd>{agent.priority}</dd></div>
              <div><dt>Checkpoints</dt><dd>{agent.checkpoint_count}</dd></div>
              <div><dt>Context</dt><dd>{agent.context_active_tokens} / {agent.context_budget_tokens} tokens</dd></div>
              <div><dt>Spill storage</dt><dd>{agent.stored_spill_bytes.toLocaleString()} bytes</dd></div>
              <div><dt>Namespaces</dt><dd>{agent.namespace_count}</dd></div>
              <div><dt>Gate</dt><dd>{agent.gate.allowed} allowed · {agent.gate.denied} denied · {agent.gate.audited} audited</dd></div>
            </dl>
            <p class="capabilities">
              <span>Capabilities:</span>
              {agent.capabilities.length ? agent.capabilities.join(', ') : 'none'}
            </p>
            {#if agent.cgroup}
              <p class="cgroup">
                Cgroup {agent.cgroup.id} ({agent.cgroup.scope}):
                {agent.cgroup.active_tool_calls}/{agent.cgroup.concurrent_tool_limit} tools,
                {agent.cgroup.context_tokens}/{agent.cgroup.context_token_limit} context tokens,
                {agent.cgroup.agent_count}/{agent.cgroup.agent_limit} agents.
              </p>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section aria-labelledby="providers-heading">
    <h2 id="providers-heading">Provider health</h2>
    {#if state.providers.length === 0}
      <p class="empty">No providers are registered in this caller scope.</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Provider</th><th>Status</th><th>API family</th><th>Failures</th><th>Probe</th></tr></thead>
          <tbody>
            {#each state.providers as provider}
              <tr>
                <th scope="row">{provider.name}<small>{provider.id} · {provider.provider_type}</small></th>
                <td>{availability(provider)}</td>
                <td>{provider.api_family}</td>
                <td>{provider.consecutive_failures}</td>
                <td>{provider.probe_duration_ms == null ? 'Not sampled' : `${provider.probe_duration_ms} ms`}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <section aria-labelledby="services-heading">
    <h2 id="services-heading">Services</h2>
    {#if state.services === null}
      <p class="unavailable">Service supervision is unavailable for this caller scope.</p>
    {:else if state.services.length === 0}
      <p class="empty">No supervised services are configured.</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Service</th><th>State</th><th>Ready</th><th>Healthy</th><th>Restarts</th><th>Last failure</th><th>Controls</th></tr></thead>
          <tbody>
            {#each state.services as service}
              <tr>
                <th scope="row">{service.name}</th>
                <td>{service.state}</td>
                <td>{service.ready ? 'Yes' : 'No'}</td>
                <td>{service.healthy ? 'Yes' : 'No'}</td>
                <td>{service.restart_count}</td>
                <td>{service.last_failure || 'None'}</td>
                <td>
                  <div class="service-actions">
                    {#if service.state === 'Inactive' || service.state === 'Failed'}
                      <button
                        on:click={() => requestServiceControl('start', service)}
                        disabled={Boolean(serviceBusy)}
                      >Start</button>
                    {:else if service.state === 'Running'}
                      <button
                        on:click={() => requestServiceControl('restart', service)}
                        disabled={Boolean(serviceBusy)}
                      >Restart</button>
                      <button
                        class="danger"
                        on:click={() => requestServiceControl('stop', service)}
                        disabled={Boolean(serviceBusy)}
                      >Stop</button>
                    {:else}
                      <span>{service.state}…</span>
                    {/if}
                    <button
                      on:click={() => loadServiceHistory(service.name)}
                      disabled={historyLoading}
                      aria-label={`View history for ${service.name}`}
                    >History</button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      {#if pendingServiceControl}
        <div class="service-confirmation" role="group" aria-labelledby="service-confirmation-heading">
          <h3 id="service-confirmation-heading">
            Confirm service {pendingServiceControl.action}
          </h3>
          <p>
            Target service: <code>{pendingServiceControl.name}</code>
            (current state {pendingServiceControl.state},
            owner {pendingServiceControl.agentId || 'none'}).
            {#if pendingServiceControl.action === 'stop'}
              Stopping ends its supervised agent and may block dependent services.
            {:else}
              Restarting replaces its supervised agent and can interrupt in-flight work.
            {/if}
            Type the exact service name to continue.
          </p>
          <label for="service-control-confirmation">Exact service name</label>
          <input
            id="service-control-confirmation"
            bind:value={serviceConfirmation}
            autocomplete="off"
            spellcheck="false"
          />
          <div class="service-actions">
            <button
              class="danger"
              on:click={() => executeServiceControl()}
              disabled={serviceConfirmation !== pendingServiceControl.name || Boolean(serviceBusy)}
            >Confirm {pendingServiceControl.action}</button>
            <button on:click={cancelServiceControl}>Cancel</button>
          </div>
        </div>
      {/if}

      {#if serviceStatus}<p class="operation-status" role="status">{serviceStatus}</p>{/if}
      {#if serviceError}<p class="operation-error" role="alert">{serviceError}</p>{/if}

      {#if historyTarget}
        <section class="service-history" aria-labelledby="service-history-heading">
          <div class="history-heading">
            <h3 id="service-history-heading">Service history: {historyTarget}</h3>
            <button
              on:click={() => loadServiceHistory(historyTarget)}
              disabled={historyLoading}
            >Refresh history</button>
          </div>
          {#if historyLoading}
            <p class="operation-status" role="status">Loading service history…</p>
          {:else if serviceHistory.length === 0}
            <p class="empty">No retained transitions for this service.</p>
          {:else}
            <div class="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Event</th><th>State</th><th>Owner</th><th>Reason</th></tr></thead>
                <tbody>
                  {#each serviceHistory as entry}
                    <tr>
                      <th scope="row">{entry.created_at}</th>
                      <td>{entry.event}</td>
                      <td>{entry.state}</td>
                      <td>{entry.agent_id || 'None'}</td>
                      <td>{entry.reason || 'None'}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </section>
      {/if}
    {/if}
  </section>

  <section aria-labelledby="packages-heading">
    <h2 id="packages-heading">Loaded packages</h2>
    {#if state.packages.length === 0}
      <p class="empty">No package-created agents are loaded in this caller scope.</p>
    {:else}
      <ul class="compact-list">
        {#each state.packages as packageInstance}
          <li>
            <strong>{packageInstance.name}</strong>
            <span>{packageInstance.agent_state} · {packageInstance.provider} · {packageInstance.profile}</span>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <section aria-labelledby="tunables-heading">
    <h2 id="tunables-heading">Operator tunables</h2>
    {#if state.tunables === null}
      <p class="unavailable">Operator tunables are unavailable for this caller scope.</p>
    {:else if state.tunables.length === 0}
      <p class="empty">No live operator tunables are registered.</p>
    {:else}
      <ul class="tunable-list">
        {#each state.tunables as tunable}
          <li class="tunable-card">
            <strong>{tunable.name}</strong>
            <p class="tunable-value">{tunable.value} · revision {tunable.revision} · {tunable.persisted ? 'persisted' : 'runtime only'}</p>
            <p>{tunable.description}</p>
            <p>Allowed range: {tunable.minimum} to {tunable.maximum}</p>
            <div class="tunable-actions">
              <button
                on:click={() => requestTunableControl('set', tunable)}
                disabled={Boolean(tunableBusy)}
                aria-label={`Set ${tunable.name}`}
              >Set value</button>
              <button
                class="danger"
                on:click={() => requestTunableControl('rollback', tunable)}
                disabled={Boolean(tunableBusy) || tunable.revision <= 1}
                aria-label={`Rollback ${tunable.name}`}
              >Rollback</button>
              <button
                on:click={() => loadTunableAudit(tunable.name)}
                disabled={tunableAuditLoading}
                aria-label={`View audit for ${tunable.name}`}
              >Audit</button>
            </div>
          </li>
        {/each}
      </ul>

      {#if pendingTunableControl}
        <div class="tunable-confirmation" role="group" aria-labelledby="tunable-confirmation-heading">
          <h3 id="tunable-confirmation-heading">
            {pendingTunableControl.action === 'set' ? 'Set' : 'Rollback'} {pendingTunableControl.name}
          </h3>
          <p>
            Frozen target: <code>{pendingTunableControl.name}</code>
            at revision {pendingTunableControl.revision}, current value
            {pendingTunableControl.value}. The server will reject this operation
            if another operator changes the revision first.
          </p>
          {#if pendingTunableControl.action === 'set'}
            <label for="tunable-control-input">
              New value ({pendingTunableControl.minimum} to {pendingTunableControl.maximum})
            </label>
          {:else}
            <p>
              Rollback changes live enforcement. Type an older retained revision,
              a vertical bar, and the exact tunable name.
            </p>
            <label for="tunable-control-input">Target revision|exact tunable name</label>
          {/if}
          <input
            id="tunable-control-input"
            bind:value={tunableInput}
            inputmode={pendingTunableControl.action === 'set' ? 'numeric' : 'text'}
            autocomplete="off"
            spellcheck="false"
          />
          <div class="tunable-actions">
            <button
              class:danger={pendingTunableControl.action === 'rollback'}
              on:click={executeTunableControl}
              disabled={!canSubmitTunableControl(pendingTunableControl, tunableInput, tunableBusy)}
            >Confirm {pendingTunableControl.action}</button>
            <button on:click={cancelTunableControl}>Cancel tunable change</button>
          </div>
        </div>
      {/if}

      {#if tunableStatus}<p class="operation-status" role="status">{tunableStatus}</p>{/if}
      {#if tunableError}<p class="operation-error" role="alert">{tunableError}</p>{/if}

      {#if tunableAuditTarget}
        <section class="tunable-audit" aria-labelledby="tunable-audit-heading">
          <div class="history-heading">
            <h3 id="tunable-audit-heading">Tunable audit: {tunableAuditTarget}</h3>
            <button
              on:click={() => loadTunableAudit(tunableAuditTarget)}
              disabled={tunableAuditLoading}
            >Refresh audit</button>
          </div>
          {#if tunableAuditLoading}
            <p class="operation-status" role="status">Loading tunable audit…</p>
          {:else if tunableAudit.length === 0}
            <p class="empty">No retained audit entries for this tunable.</p>
          {:else}
            <div class="table-wrap">
              <table>
                <thead><tr><th>Time</th><th>Action</th><th>Outcome</th><th>Revision</th><th>Value</th><th>Actor</th><th>Reason</th></tr></thead>
                <tbody>
                  {#each tunableAudit as entry}
                    <tr>
                      <th scope="row">{entry.created_at}</th>
                      <td>{entry.action}</td>
                      <td>{entry.outcome}</td>
                      <td>{entry.revision ?? 'None'}</td>
                      <td>{entry.effective_value ?? 'None'}</td>
                      <td>{entry.actor}</td>
                      <td>{entry.reason || 'None'}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </section>
      {/if}
    {/if}
  </section>
</section>

<style>
  .operations { padding: 1.5rem; overflow-y: auto; }
  header p { max-width: 54rem; color: #b9b9c8; line-height: 1.5; }
  h1 { margin: 0 0 0.5rem; font-size: 1.3rem; }
  h2 { margin: 1.75rem 0 0.75rem; font-size: 1rem; color: #d8d8e3; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.75rem; margin: 1.25rem 0; }
  .summary div, .agent-grid > li, .compact-list li, .tunable-card { background: #1a1a2e; border: 1px solid #3f3f5a; border-radius: 8px; }
  .summary div { padding: 0.8rem; }
  .summary dt, .details dt { color: #b9b9c8; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; }
  .summary dd { margin: 0.3rem 0 0; font-weight: 650; }
  .agent-grid, .compact-list { padding: 0; margin: 0; list-style: none; }
  .agent-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 0.75rem; }
  .agent-grid > li { padding: 0.9rem; }
  .title-row { display: flex; align-items: center; gap: 0.55rem; }
  .pill { margin-left: auto; padding: 0.15rem 0.45rem; border-radius: 999px; background: #2c2c45; font-size: 0.72rem; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #a7a7b8; }
  .dot.running { background: #4ade80; }
  .dot.paused { background: #fbbf24; }
  .dot.stopped { background: #f87171; }
  .details { display: grid; grid-template-columns: 1fr 1fr; gap: 0.55rem; margin: 0.9rem 0; }
  .details dd { margin: 0.15rem 0 0; font-size: 0.8rem; }
  .capabilities, .cgroup { margin: 0.5rem 0 0; color: #b9b9c8; font-size: 0.78rem; line-height: 1.45; }
  .capabilities span { color: #d8d8e3; }
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; background: #1a1a2e; border: 1px solid #3f3f5a; font-size: 0.8rem; }
  th, td { padding: 0.65rem; border-bottom: 1px solid #34344b; text-align: left; }
  thead th { color: #b9b9c8; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; }
  tbody th { font-weight: 600; }
  small { display: block; margin-top: 0.2rem; color: #a7a7b8; font-weight: 400; }
  .compact-list { display: grid; gap: 0.5rem; }
  .compact-list li { display: flex; justify-content: space-between; gap: 1rem; padding: 0.7rem; }
  .compact-list span { color: #b9b9c8; }
  .tunable-list { display: grid; gap: 0.5rem; margin: 0; padding: 0; list-style: none; }
  .tunable-card { padding: 0.75rem; }
  .tunable-list p { margin: 0; color: #a7a7b8; font-size: 0.78rem; }
  .tunable-list .tunable-value { margin: 0.3rem 0; color: #b9b9c8; }
  .empty { color: #b9b9c8; font-size: 0.85rem; }
  .unavailable { padding: 0.75rem; border: 1px solid #6b531c; border-radius: 8px; background: #352a12; color: #fde68a; }
  .service-actions { display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; }
  .service-actions button, .history-heading button {
    min-height: 40px;
    padding: 0.35rem 0.65rem;
    border: 1px solid #5b5b76;
    border-radius: 6px;
    background: #29293f;
    color: #e8e8f0;
    cursor: pointer;
  }
  .service-actions button:disabled, .history-heading button:disabled { opacity: 0.5; cursor: wait; }
  .service-actions .danger, .tunable-actions .danger { background: #581717; border-color: #991b1b; color: #fecaca; }
  .service-confirmation { margin-top: 0.9rem; padding: 0.9rem; border: 1px solid #b91c1c; border-radius: 8px; background: #2b1518; }
  .service-confirmation h3 { margin: 0 0 0.5rem; }
  .service-confirmation p { color: #fecaca; line-height: 1.45; overflow-wrap: anywhere; }
  .service-confirmation label { display: block; margin-bottom: 0.35rem; font-weight: 700; }
  .service-confirmation input { width: 100%; min-height: 44px; border: 1px solid #77778e; border-radius: 7px; background: #11111d; color: #f5f5fa; padding: 0.5rem 0.65rem; }
  .operation-status { color: #93c5fd; }
  .operation-error { color: #fca5a5; overflow-wrap: anywhere; }
  .service-history { margin-top: 1rem; }
  .tunable-actions { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.7rem; }
  .tunable-actions button {
    min-height: 40px;
    padding: 0.35rem 0.65rem;
    border: 1px solid #5b5b76;
    border-radius: 6px;
    background: #29293f;
    color: #e8e8f0;
    cursor: pointer;
  }
  .tunable-actions button:disabled { opacity: 0.5; cursor: wait; }
  .tunable-confirmation { margin-top: 0.9rem; padding: 0.9rem; border: 1px solid #b91c1c; border-radius: 8px; background: #2b1518; }
  .tunable-confirmation h3 { margin: 0 0 0.5rem; }
  .tunable-confirmation p { color: #fecaca; line-height: 1.45; overflow-wrap: anywhere; }
  .tunable-confirmation label { display: block; margin-bottom: 0.35rem; font-weight: 700; }
  .tunable-confirmation input { width: 100%; min-height: 44px; border: 1px solid #77778e; border-radius: 7px; background: #11111d; color: #f5f5fa; padding: 0.5rem 0.65rem; }
  .tunable-audit { margin-top: 1rem; }
  .history-heading { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
  .history-heading h3 { margin: 0; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  @media (max-width: 700px) {
    .operations { padding: 1rem; }
    .agent-grid { grid-template-columns: 1fr; }
    .details { grid-template-columns: 1fr; }
    .compact-list li { flex-direction: column; }
  }
</style>

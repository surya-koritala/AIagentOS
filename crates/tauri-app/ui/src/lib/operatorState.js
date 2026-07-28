export function createOperatorState() {
  return {
    phase: 'loading',
    agents: [],
    totalVisibleAgents: 0,
    agentsTruncated: false,
    scope: 'unknown',
    consistency: 'unknown',
    kernelVersion: 'unknown',
    protocolVersion: 0,
    providers: [],
    packages: [],
    services: null,
    tunables: null,
    scopedGate: { allowed: 0, denied: 0, audited: 0 },
    metrics: null,
    lastSuccessAt: null,
    error: null,
    warnings: [],
    reconnectGeneration: 0,
    reconnected: false,
    refreshing: false,
    operation: null,
  };
}

export function beginRefresh(state) {
  return {
    ...state,
    refreshing: true,
    error: null,
    reconnected: false,
  };
}

export function applyOperatorView(state, view) {
  const warnings = Array.isArray(view.warnings) ? view.warnings : [];
  const generation = Number(view.reconnect_generation || 0);
  return {
    ...state,
    phase: warnings.length > 0 ? 'partial' : 'fresh',
    agents: Array.isArray(view.agents) ? view.agents : [],
    totalVisibleAgents: Number(view.total_visible_agents || 0),
    agentsTruncated: Boolean(view.agents_truncated),
    scope: view.scope || 'unknown',
    consistency: view.consistency || 'unknown',
    kernelVersion: view.kernel_version || 'unknown',
    protocolVersion: Number(view.protocol_version || 0),
    providers: Array.isArray(view.providers) ? view.providers : [],
    packages: Array.isArray(view.packages) ? view.packages : [],
    services: Array.isArray(view.services) ? view.services : null,
    tunables: Array.isArray(view.tunables) ? view.tunables : null,
    scopedGate: view.scoped_gate ?? { allowed: 0, denied: 0, audited: 0 },
    metrics: view.metrics ?? null,
    lastSuccessAt: view.captured_at || state.lastSuccessAt,
    error: null,
    warnings,
    reconnectGeneration: generation,
    reconnected: generation > state.reconnectGeneration,
    refreshing: false,
  };
}

export function failRefresh(state, error) {
  return {
    ...state,
    phase: 'stale',
    error: String(error),
    warnings: [],
    reconnected: false,
    refreshing: false,
  };
}

export function beginOperation(state, label) {
  return { ...state, operation: String(label) };
}

export function finishOperation(state, label) {
  if (state.operation !== String(label)) return state;
  return { ...state, operation: null };
}

export function statusMessage(state) {
  if (state.operation) return `Working: ${state.operation}`;
  if (state.refreshing) return 'Refreshing operator data…';
  if (state.phase === 'stale') {
    return `Connection lost — showing last known data. ${state.error || ''}`.trim();
  }
  if (state.phase === 'partial') {
    const recovered = state.reconnected
      ? `Reconnected to the service (generation ${state.reconnectGeneration}). `
      : '';
    return `${recovered}${state.warnings.join(' ')}`;
  }
  if (state.reconnected) {
    return `Reconnected to the service (generation ${state.reconnectGeneration}).`;
  }
  if (state.phase === 'fresh') return `Data current as of ${state.lastSuccessAt}.`;
  return 'Loading operator data…';
}

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  applyOperatorView,
  beginOperation,
  beginRefresh,
  createOperatorState,
  failRefresh,
  finishOperation,
  statusMessage,
} from './operatorState.js';

const view = {
  captured_at: '2026-07-28T12:00:00Z',
  agents: [{ id: 'agent-1', name: 'worker', state: 'Running', priority: 3 }],
  total_visible_agents: 1,
  agents_truncated: false,
  scope: 'global',
  consistency: 'atomic',
  kernel_version: '0.3.0',
  protocol_version: 2,
  providers: [{ id: 'stub', available: true, circuit_open: false }],
  packages: [{ agent_id: 'agent-1', name: 'reviewer' }],
  installed_packages: [{
    name: 'reviewer',
    version: '2.0.0',
    digest: 'a'.repeat(64),
    publisher: 'fixture-publisher',
  }],
  services: [{ name: 'worker', state: 'Running' }],
  tunables: [{ name: 'kernel.max_agents', value: 10 }],
  scoped_gate: { allowed: 7, denied: 1, audited: 2 },
  metrics: { tokens_consumed: 10, api_calls_made: 2, time_elapsed_ms: 1000 },
  warnings: [],
  reconnect_generation: 0,
};

test('failed refresh preserves last-known-good values and marks them stale', () => {
  const fresh = applyOperatorView(createOperatorState(), view);
  const stale = failRefresh(beginRefresh(fresh), new Error('connection refused'));

  assert.equal(stale.phase, 'stale');
  assert.deepEqual(stale.agents, fresh.agents);
  assert.deepEqual(stale.providers, fresh.providers);
  assert.deepEqual(stale.installedPackages, fresh.installedPackages);
  assert.deepEqual(stale.services, fresh.services);
  assert.deepEqual(stale.tunables, fresh.tunables);
  assert.deepEqual(stale.metrics, fresh.metrics);
  assert.match(stale.error, /connection refused/);
  assert.match(statusMessage(stale), /showing last known data/);
  assert.match(statusMessage(stale), /connection refused/);
});

test('scoped omissions are visibly partial and do not invent global zeroes', () => {
  const partial = applyOperatorView(createOperatorState(), {
    ...view,
    metrics: null,
    installed_packages: null,
    services: null,
    tunables: null,
    warnings: ['Global metrics are unavailable for this caller scope.'],
  });

  assert.equal(partial.phase, 'partial');
  assert.equal(partial.metrics, null);
  assert.equal(partial.installedPackages, null);
  assert.equal(partial.services, null);
  assert.equal(partial.tunables, null);
  assert.match(statusMessage(partial), /unavailable/);
});

test('operator sections are projected without losing scope or enforcement counters', () => {
  const state = applyOperatorView(createOperatorState(), view);

  assert.equal(state.scope, 'global');
  assert.equal(state.consistency, 'atomic');
  assert.equal(state.kernelVersion, '0.3.0');
  assert.equal(state.protocolVersion, 2);
  assert.equal(state.totalVisibleAgents, 1);
  assert.equal(state.agentsTruncated, false);
  assert.equal(state.providers[0].id, 'stub');
  assert.equal(state.packages[0].name, 'reviewer');
  assert.equal(state.installedPackages[0].version, '2.0.0');
  assert.equal(state.services[0].name, 'worker');
  assert.equal(state.tunables[0].name, 'kernel.max_agents');
  assert.deepEqual(state.scopedGate, { allowed: 7, denied: 1, audited: 2 });
});

test('a higher generation identifies a recovered server connection', () => {
  const first = applyOperatorView(createOperatorState(), view);
  const recovered = applyOperatorView(first, {
    ...view,
    reconnect_generation: 1,
  });

  assert.equal(recovered.reconnected, true);
  assert.equal(recovered.reconnectGeneration, 1);
  assert.match(statusMessage(recovered), /Reconnected/);
});

test('long-running operations stay visible until their matching completion', () => {
  const working = beginOperation(createOperatorState(), 'waiting for agent turn');
  assert.equal(statusMessage(working), 'Working: waiting for agent turn');
  assert.equal(finishOperation(working, 'different operation'), working);
  assert.equal(finishOperation(working, 'waiting for agent turn').operation, null);
});

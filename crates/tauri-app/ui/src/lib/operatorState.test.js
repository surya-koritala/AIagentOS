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
  metrics: { tokens_consumed: 10, api_calls_made: 2, time_elapsed_ms: 1000 },
  warnings: [],
  reconnect_generation: 0,
};

test('failed refresh preserves last-known-good values and marks them stale', () => {
  const fresh = applyOperatorView(createOperatorState(), view);
  const stale = failRefresh(beginRefresh(fresh), new Error('connection refused'));

  assert.equal(stale.phase, 'stale');
  assert.deepEqual(stale.agents, fresh.agents);
  assert.deepEqual(stale.metrics, fresh.metrics);
  assert.match(stale.error, /connection refused/);
  assert.match(statusMessage(stale), /showing last known data/);
  assert.match(statusMessage(stale), /connection refused/);
});

test('scoped omissions are visibly partial and do not invent global zeroes', () => {
  const partial = applyOperatorView(createOperatorState(), {
    ...view,
    metrics: null,
    warnings: ['Global metrics are unavailable for this caller scope.'],
  });

  assert.equal(partial.phase, 'partial');
  assert.equal(partial.metrics, null);
  assert.match(statusMessage(partial), /unavailable/);
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

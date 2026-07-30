import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

function source(name) {
  return readFileSync(new URL(name, import.meta.url), 'utf8');
}

test('desktop shell retains keyboard, focus, and reduced-motion contracts', () => {
  const app = source('../App.svelte');
  const entrypoint = source('../main.js');

  assert.match(app, /href="#main-content">Skip to main content/);
  assert.match(app, /id="main-content" tabindex="-1"/);
  assert.match(app, /:global\(:focus-visible\)/);
  assert.match(app, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(app, /role="status"/);
  assert.match(entrypoint, /import \{ mount \} from 'svelte'/);
  assert.match(entrypoint, /mount\(App,/);
  assert.doesNotMatch(entrypoint, /new App\(/);
});

test('setup and chat controls retain names and modal keyboard containment', () => {
  const setup = source('SetupModal.svelte');
  const chat = source('ChatPanel.svelte');

  for (const contract of [
    'role="dialog"',
    'aria-modal="true"',
    'aria-labelledby="setup-title"',
    'aria-describedby="setup-description"',
    'function trapFocus(event)',
    'firstControl?.focus()',
  ]) {
    assert.ok(setup.includes(contract), `setup modal lost ${contract}`);
  }

  for (const contract of [
    'role="log"',
    'aria-live="polite"',
    'for="chat-message"',
    'id="chat-message"',
    'aria-label="Send message"',
  ]) {
    assert.ok(chat.includes(contract), `chat panel lost ${contract}`);
  }
});

test('primary navigation exposes current state and no fabricated activity', () => {
  const sidebar = source('Sidebar.svelte');
  const dashboard = source('Dashboard.svelte');
  const status = source('AgentStatus.svelte');

  assert.match(sidebar, /<nav aria-label="Primary">/);
  assert.match(sidebar, /aria-current=/);
  assert.match(sidebar, /aria-label=\{showNewAgent/);
  assert.match(dashboard, /dispatch\('select', agent\.id\)/);
  assert.doesNotMatch(dashboard, /dispatch\('select', \{ detail:/);
  assert.match(status, /This view is not an event history\./);
  assert.doesNotMatch(status, /simulated|time:\s*['"]now['"]|Activity Feed/i);
});

test('stream cancellation and checkpoint deletion retain explicit target contracts', () => {
  const chat = source('ChatPanel.svelte');
  const detail = source('AgentDetail.svelte');

  assert.match(chat, /new Channel\(\)/);
  assert.match(chat, /invoke\('stream_message'/);
  assert.match(chat, /invoke\('cancel_message'/);
  assert.match(chat, /requestId: target\.requestId/);
  assert.match(chat, /agentId: target\.agentId/);
  assert.match(chat, /Cancel turn/);

  assert.match(detail, /invoke\('list_checkpoints'/);
  assert.match(detail, /invoke\('resume_checkpoint'/);
  assert.match(detail, /invoke\('delete_checkpoint'/);
  assert.match(detail, /confirmCheckpointId: checkpointDeleteConfirmation/);
  assert.match(detail, /Type the exact checkpoint\s+ID to continue/);
  assert.match(
    detail,
    /checkpointDeleteConfirmation !== pendingCheckpointDelete\.checkpointId/,
  );
  assert.match(detail, /const targetAgentId = pendingCheckpointDelete\.agentId/);
});

test('service supervision retains public commands and frozen exact-target confirmation', () => {
  const app = source('../App.svelte');
  const status = source('AgentStatus.svelte');

  assert.match(app, /<AgentStatus[\s\S]*on:refresh=\{refreshOperator\}/);
  assert.match(status, /invoke\(`\$\{frozenTarget\.action\}_service`, args\)/);
  assert.match(status, /invoke\('service_history'/);
  assert.match(status, /const frozenTarget = \{ \.\.\.target \}/);
  assert.match(status, /confirmServiceName = serviceConfirmation/);
  assert.match(
    status,
    /serviceConfirmation !== pendingServiceControl\.name/,
  );
  assert.match(status, /Type the exact service name to continue/);
  assert.match(status, /may block dependent services/);
  assert.match(status, /can interrupt in-flight work/);
});

test('software update requires review and exact-version confirmation', () => {
  const settings = source('Settings.svelte');

  for (const contract of [
    "invoke('check_for_update')",
    "invoke('install_update', { expectedVersion })",
    'Review install {availableUpdate.version}',
    'Confirm update {availableUpdate.version}',
    '`Confirm install ${availableUpdate.version}`',
    'must match the updater signature built into this app',
  ]) {
    assert.ok(settings.includes(contract), `software updater lost ${contract}`);
  }
});

test('operator tunables retain revision bounds, exact rollback target, and audit controls', () => {
  const status = source('AgentStatus.svelte');

  assert.match(status, /const frozenTarget = \{ \.\.\.pendingTunableControl \}/);
  assert.match(status, /invoke\('set_operator_tunable'/);
  assert.match(status, /invoke\('rollback_operator_tunable'/);
  assert.match(status, /invoke\('operator_tunable_audit'/);
  assert.match(status, /expectedRevision: frozenTarget\.revision/);
  assert.match(status, /confirmTunableName: frozenTarget\.name/);
  assert.match(status, /revision >= target\.revision/);
  assert.match(status, /Target revision\|exact tunable name/);
  assert.match(status, /another operator changes the revision first/);
});

test('system audit remains explicit, bounded, non-atomic, and accessible', () => {
  const status = source('AgentStatus.svelte');

  assert.match(status, /invoke\('get_system_audit', \{ limit: 50 \}\)/);
  assert.match(status, /aria-labelledby="system-audit-heading"/);
  assert.match(status, /aria-label=\{systemAudit === null \? 'Load system audit' : 'Refresh system audit'\}/);
  assert.match(status, /bounded sequential public-API reads, not an atomic cross-ledger/);
  assert.match(status, /Node-control history/);
  assert.match(status, /Cluster-membership history/);
  assert.match(status, /Certificate-rollout history/);
  assert.match(status, /systemAudit\.cluster_certificate_rollout === null/);
  assert.match(status, /No empty history has been assumed/);
  assert.match(status, /role="status"/);
  assert.match(status, /role="alert"/);
  assert.match(status, /showing the last successfully loaded audit/);
});

test('signed package controls freeze version and digest on the public command boundary', () => {
  const status = source('AgentStatus.svelte');

  assert.match(status, /invoke\('install_package'/);
  assert.match(status, /invoke\('run_installed_package'/);
  assert.match(status, /invoke\('rollback_installed_package'/);
  assert.match(status, /invoke\('remove_installed_package'/);
  assert.match(status, /const frozenTarget = \{ \.\.\.pendingPackageControl \}/);
  assert.match(status, /expectedVersion: frozenTarget\.version/);
  assert.match(status, /expectedDigest: frozenTarget\.digest/);
  assert.match(status, /confirmPackageTarget: packageConfirmation/);
  assert.match(
    status,
    /packageConfirmation !== `\$\{pendingPackageControl\.version\}\|\$\{pendingPackageControl\.name\}`/,
  );
  assert.match(status, /Version\|exact package name/);
  assert.match(status, /rejects a concurrent change/);
  assert.match(status, /prevents new runs from this package/);
});

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
  const status = source('AgentStatus.svelte');

  assert.match(sidebar, /<nav aria-label="Primary">/);
  assert.match(sidebar, /aria-current=/);
  assert.match(sidebar, /aria-label=\{showNewAgent/);
  assert.match(status, /This view is not an event history\./);
  assert.doesNotMatch(status, /simulated|time:\s*['"]now['"]|Activity Feed/i);
});

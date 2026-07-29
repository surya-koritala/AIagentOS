import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const operatorView = {
  scope: 'system',
  consistency: 'atomic',
  kernel_version: 'agent-kernel/1.0.0',
  protocol_version: 1,
  captured_at: '2026-07-28T20:00:00Z',
  reconnect_generation: 0,
  total_visible_agents: 1,
  agents_truncated: false,
  warnings: [],
  agents: [
    {
      id: 'agent-1',
      name: 'Research agent',
      state: 'Running',
      scheduler_state: 'Ready',
      sandbox_active: true,
      priority: 5,
      checkpoint_count: 2,
      context_active_tokens: 128,
      context_budget_tokens: 4096,
      stored_spill_bytes: 0,
      namespace_count: 1,
      capabilities: ['web.read'],
      gate: { allowed: 4, denied: 1, audited: 5 },
      cgroup: null,
    },
  ],
  providers: [
    {
      id: 'provider-1',
      name: 'Local fixture',
      provider_type: 'local',
      api_family: 'openai-compatible',
      available: true,
      circuit_open: false,
      probe_timed_out: false,
      probe_duration_ms: 12,
      consecutive_failures: 0,
    },
  ],
  packages: [],
  services: [
    {
      name: 'research-worker',
      state: 'Running',
      agent_id: 'agent-1',
      restart_count: 1,
      desired_running: true,
      ready: true,
      healthy: true,
      restart_exhausted: false,
      last_failure: null,
      next_restart_at: null,
      last_transition_at: '2026-07-28T19:55:00Z',
    },
  ],
  tunables: [],
  scoped_gate: { allowed: 4, denied: 1, audited: 5 },
  metrics: { tokens_consumed: 128, api_calls_made: 3 },
};

const checkpoints = [
  {
    id: '11111111-2222-4333-8444-555555555555',
    agent_id: 'agent-1',
    version: 1,
    provider_id: 'provider-1',
    model_id: 'fixture-model',
    created_at: '2026-07-28T19:00:00Z',
    expires_at: '2026-07-29T19:00:00Z',
  },
];

const serviceHistory = [
  {
    id: 1,
    name: 'research-worker',
    event: 'started',
    state: 'Running',
    agent_id: 'agent-1',
    reason: null,
    created_at: '2026-07-28T19:55:00Z',
  },
];

async function installTauriFixture(page, { setupComplete = true } = {}) {
  await page.addInitScript(
    ({ complete, snapshot, checkpointFixtures, serviceHistoryFixtures }) => {
      const config = {
        setup_complete: complete,
        llm_provider: 'azure-openai',
        configured_providers: ['azure-openai'],
        credential_store_available: true,
        azure_endpoint: 'https://fixture.invalid',
        azure_deployment: 'fixture-model',
        local_endpoint: 'http://127.0.0.1:11434',
        data_dir: '/tmp/fixture',
      };

      window.__TAURI_INTERNALS__ = {
        invoke(command) {
          if (command === 'load_config') return Promise.resolve(config);
          if (command === 'get_operator_view') return Promise.resolve(snapshot);
          if (command === 'list_checkpoints') return Promise.resolve(checkpointFixtures);
          if (command === 'resume_checkpoint') {
            return Promise.resolve({ state: 'Running', output: null });
          }
          if (command === 'delete_checkpoint') return Promise.resolve(true);
          if (command === 'service_history') {
            return Promise.resolve(serviceHistoryFixtures);
          }
          if (command === 'start_service' || command === 'stop_service' || command === 'restart_service') {
            return Promise.resolve({
              ...snapshot.services[0],
              state: command === 'stop_service' ? 'Inactive' : 'Running',
            });
          }
          return Promise.reject(new Error(`Unexpected rendered-test command: ${command}`));
        },
      };
    },
    {
      complete: setupComplete,
      snapshot: operatorView,
      checkpointFixtures: checkpoints,
      serviceHistoryFixtures: serviceHistory,
    },
  );
}

async function expectWcagAxeClean(page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();

  expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
}

test('production dashboard, status, and settings views pass rendered WCAG checks', async ({ page }) => {
  await installTauriFixture(page);
  await page.goto('/');

  await expect(page.getByRole('heading', { name: 'AI Agent OS' })).toBeVisible();
  await expectWcagAxeClean(page);

  await page.getByRole('button', { name: 'Agent status' }).click();
  await expect(page.getByRole('heading', { name: 'Operations' })).toBeVisible();
  await expectWcagAxeClean(page);

  await page.getByRole('button', { name: 'Settings' }).click();
  await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  await expectWcagAxeClean(page);
});

test('skip link and primary navigation are keyboard operable with visible focus', async ({ page }) => {
  await installTauriFixture(page);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'AI Agent OS' })).toBeVisible();

  await page.keyboard.press('Tab');
  const skipLink = page.getByRole('link', { name: 'Skip to main content' });
  await expect(skipLink).toBeFocused();
  await expect(skipLink).toHaveCSS('outline-style', 'solid');

  await page.keyboard.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();

  await page.reload();
  await expect(page.getByRole('heading', { name: 'AI Agent OS' })).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(skipLink).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Dashboard' })).toBeFocused();
});

test('setup dialog is named, axe-clean, and contains keyboard focus', async ({ page }) => {
  await installTauriFixture(page, { setupComplete: false });
  await page.goto('/');

  const dialog = page.getByRole('dialog', { name: 'Welcome to AI Agent OS' });
  await expect(dialog).toBeVisible();
  const provider = page.getByRole('combobox', { name: 'Provider', exact: true });
  const continueButton = page.getByRole('button', { name: /Save & Continue/ });
  await expect(provider).toBeFocused();
  await expectWcagAxeClean(page);

  await page.keyboard.press('Shift+Tab');
  await expect(continueButton).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(provider).toBeFocused();
});

test('dashboard reflows at a 320 CSS-pixel viewport without page-level horizontal scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await installTauriFixture(page);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'AI Agent OS' })).toBeVisible();

  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    document: document.documentElement.scrollWidth,
  }));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.viewport);
});

test('reduced-motion preference suppresses nonessential transitions', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await installTauriFixture(page);
  await page.goto('/');
  const agentCard = page.getByRole('button', { name: /Open Research agent/ });
  await expect(agentCard).toBeVisible();

  const durations = await agentCard.evaluate(element => {
    const style = getComputedStyle(element);
    return {
      animation: style.animationDuration,
      transition: style.transitionDuration,
    };
  });
  const durationSeconds = value => Math.max(...value.split(',').map(Number.parseFloat));
  expect(durationSeconds(durations.animation)).toBeLessThanOrEqual(0.00001);
  expect(durationSeconds(durations.transition)).toBeLessThanOrEqual(0.00001);
});

test('checkpoint controls are axe-clean and require exact-target deletion confirmation', async ({ page }) => {
  await installTauriFixture(page);
  await page.goto('/');
  await page.getByRole('button', { name: /Open Research agent/ }).click();

  await expect(
    page.getByRole('heading', { name: 'Generation checkpoints' }),
  ).toBeVisible();
  await expect(
    page.getByText('11111111-2222-4333-8444-555555555555', { exact: true }),
  ).toBeVisible();
  await expectWcagAxeClean(page);

  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  const confirmation = page.getByRole('group', {
    name: 'Confirm permanent checkpoint deletion',
  });
  await expect(confirmation).toBeVisible();
  const permanentDelete = page.getByRole('button', {
    name: 'Permanently delete',
  });
  await expect(permanentDelete).toBeDisabled();
  await page
    .getByRole('textbox', { name: 'Exact checkpoint ID' })
    .fill('11111111-2222-4333-8444-555555555555');
  await expect(permanentDelete).toBeEnabled();
  await expectWcagAxeClean(page);
});

test('service controls freeze the target and require exact-name confirmation', async ({ page }) => {
  await installTauriFixture(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'Agent status' }).click();

  await expect(page.getByRole('heading', { name: 'Services' })).toBeVisible();
  await page.getByRole('button', { name: 'Stop', exact: true }).click();
  const confirmation = page.getByRole('group', {
    name: 'Confirm service stop',
  });
  await expect(confirmation).toContainText('research-worker');
  await expect(confirmation).toContainText('may block dependent services');

  const confirmStop = page.getByRole('button', { name: 'Confirm stop' });
  await expect(confirmStop).toBeDisabled();
  await page
    .getByRole('textbox', { name: 'Exact service name' })
    .fill('research-worker');
  await expect(confirmStop).toBeEnabled();
  await expectWcagAxeClean(page);

  await page.getByRole('button', { name: 'Cancel' }).click();
  await page
    .getByRole('button', { name: 'View history for research-worker' })
    .click();
  await expect(
    page.getByRole('heading', { name: 'Service history: research-worker' }),
  ).toBeVisible();
  await expect(page.getByText('started', { exact: true })).toBeVisible();
  await expectWcagAxeClean(page);
});

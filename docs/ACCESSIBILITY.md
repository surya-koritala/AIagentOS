# Desktop accessibility qualification

## Target and current status

The Tauri/Svelte desktop client targets **WCAG 2.2 Level AA** for supported
desktop platforms. This target is not a completed certification claim. It is a
release criterion under
[issue #126](https://github.com/surya-koritala/AIagentOS/issues/126).

The checked-in baseline provides semantic landmarks and headings, a skip link,
visible keyboard focus, named form and icon-only controls, current-page state,
modal focus containment, live status and conversation regions, text alongside
color status, minimum control targets, and reduced-motion behavior. The
operator status screen renders only the latest public operator snapshot and
explicitly says that it is not an event history; it does not fabricate event
times or activity.

## Blocking automated checks

The frontend CI job runs all of the following on every pull request:

```bash
cd crates/tauri-app/ui
npm ci
npm run check
npm test
npx playwright install --with-deps chromium
npm run test:a11y
```

`svelte-check --fail-on-warnings` treats Svelte compiler accessibility
diagnostics as failures. `accessibility.test.js` retains source-level contracts
for keyboard focus, reduced motion, modal semantics and focus containment,
control names, live regions, current navigation state, and the prohibition on
simulated activity.

`npm run test:a11y` builds the production frontend bundle, serves that exact
bundle on loopback, and uses a lockfile-pinned Playwright Chromium with
`@axe-core/playwright`. A deterministic in-page Tauri IPC fixture supplies
non-secret setup and operator snapshots. The rendered suite scans the dashboard,
operator status, settings, and setup dialog against WCAG 2 A/AA, 2.1 A/AA, and
2.2 AA axe rules. It also proves keyboard skip-link navigation, visible focus,
setup-dialog focus containment, page-level reflow at a 320 CSS-pixel viewport,
and reduced-motion suppression. Browser traces and screenshots are retained only
for failed CI cases.

These checks prevent known regressions but do not replace assistive-technology
testing, exact native-webview testing, platform text scaling, visual inspection,
or user testing. Automated contrast and reflow checks reduce risk; the manual
matrix below remains authoritative for the signed release candidate.

## Manual release checklist

Run this checklist against each exact release-candidate desktop artifact on
Windows, macOS, and the supported Linux desktop before marking the accessibility
acceptance item complete. Record the OS, artifact digest, tester, assistive
technology/version, date, results, and linked findings.

- [ ] Complete setup, navigation, agent creation, chat, lifecycle actions,
      settings, retry, and status inspection using the keyboard only.
- [ ] Verify focus is always visible, follows a logical order, enters and stays
      within setup while the modal is open, and is not obscured.
- [ ] Verify the skip link moves focus to the main content.
- [ ] Verify every control has an accurate accessible name and current/disabled/
      busy/error state is announced.
- [ ] Verify the setup dialog, status banner, operation progress, errors,
      conversation log, and newly added messages are announced without
      disruptive repetition.
- [ ] Verify agent state and errors remain understandable without color or
      emoji.
- [ ] Verify text and non-text contrast with a measurement tool against WCAG
      2.2 AA thresholds.
- [ ] Verify the interface at 200% text size and 400% zoom/reflow without lost
      content or two-dimensional scrolling except where essential.
- [ ] Enable reduced motion and verify nonessential animation and transitions
      stop.
- [ ] Verify pointer targets meet the chosen WCAG 2.2 target-size exception and
      that adjacent targets are not easily activated by mistake.
- [ ] Test with Narrator on Windows, VoiceOver on macOS, and the documented Linux
      screen reader on the supported desktop profile.
- [ ] Resolve or explicitly waive every finding through the release-governance
      process; a waiver records impact, scope, owner, and expiry.

Until this matrix is executed against signed exact-release artifacts and all
blocking findings are closed, the desktop client remains below
Production-qualified and the accessibility checkbox in #126 remains open.

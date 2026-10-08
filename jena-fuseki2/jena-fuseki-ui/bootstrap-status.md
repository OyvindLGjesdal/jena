# Bootstrap 6 alpha in the Fuseki UI: status

Experiment date: 2026-10-08. Bootstrap version: `6.0.0-alpha.1`, published to npm the same day.

The goal is to migrate `jena-fuseki-ui` from Bootstrap 5.3 to the 6.0 alpha. That gives Jena a head start for when v6 is stable, and gives the Bootstrap project feedback on the alpha.

## Summary

- The migration works. The UI builds, all unit tests pass, and the e2e suite passes apart from one flaky test that predates the migration (see [Upload bug found on the way](#upload-bug-found-on-the-way)).
- A screenshot comparison of every page, v5 against v6, found five Fuseki regressions. All five are fixed.
- The experiment found several alpha issues. None of them had a Bootstrap issue on 2026-10-08.
- Dark mode is turned off for now, because YASQE/YASR, CodeMirror and the logo do not support it.

## Where things are

| What | Where |
|---|---|
| Migration commit | `c684060f13 bootstrap alpha` on branch `bootstrap6-alpha` |
| Earlier attempt (Aug 2026, docs only) | branch `bootstrap-6-test` (used `6.0.0-alpha1`, which does not exist; the real version is dotted) |
| Screenshots, v5 and v6 | `tests/e2e/screenshots/screenshots.cy.js/` (gitignored; the v6 files show the state after the fixes) |
| Video tour of v6 | `tests/e2e/videos/tour.cy.js.mp4` (gitignored, 51 s) |
| Migration guide used | `skills/bootstrap-v5-v6-migration/SKILL.md` and `site/src/content/docs/guides/migration.mdx` in twbs/bootstrap |

Bootstrap's `AGENTS.md` is for contributors to Bootstrap itself. It is not a migration guide.

## Installation

The repo's `.yarnrc.yml` has `npmMinimalAgeGate: 2d`. Yarn therefore quarantined the alpha (`YN0016`). It was installed once with `YARN_NPM_MINIMAL_AGE_GATE=0 yarn add bootstrap@6.0.0-alpha.1`, and `.yarnrc.yml` was not changed.

`yarn install --immutable` passes locally with the lockfile. A clean CI cache can still hit the gate until about 2026-10-10 16:47 UTC. That was not tested.

## Migration changes

- **Dependencies.** `bootstrap` 5.3 became `6.0.0-alpha.1`, and `@popperjs/core` was removed. No new packages were added.
- **CSS.** `main.js` imports the prebuilt `bootstrap/dist/css/bootstrap.min.css`, and the Bootstrap Sass source is no longer compiled. Self-compiled Sass emits unprefixed tokens (`--spacer`), but the bundle JS reads `--bs-*` names, so mixing the two needs an extra PostCSS step. `index.scss` uses `var(--bs-gray-600)` and similar tokens in place of Sass variables, and every `@import` became `@use`.
- **JS.** All imports come from `bootstrap/dist/js/bootstrap.bundle.min.js`, which includes Floating UI. The old code loaded the bundle and the ESM build, so it shipped two copies of Bootstrap.
- **Classes.**
  - Breakpoints are prefixes now (`col-md-6` became `md:col-6`, `me-md-2` became `md:me-3`).
  - Spacers were remapped to keep v5 sizes (2→3, 3→5, 4→7, 5→12).
  - Button colours: `btn btn-primary` became `btn-solid theme-primary`.
  - Alerts, badges and text colours: `alert-*`, `text-bg-*` and `text-danger` became `theme-*` and `fg-danger`.
  - Forms: `form-select` became `form-control`, and `has-validation` is gone.
  - `placeholder-glow` became `placeholder-pulse`.
  - Type: `display-4` became `fs-5xl fw-light`, and `lead` became `fs-lg fw-light`.
- **Radios.** `.form-check` / `.form-check-input` became `.form-field` with `.radio`.
- **Navbar.** The Collapse became a `<dialog class="drawer">`, and `navbar-expand-md` became `md:navbar-expand`. A route watcher closes the drawer after navigation, because on phones the modal drawer otherwise stays open over the new page.
- **Toast.** The header uses `bg-*` with `fg-contrast-*`, and `btn-close-white` is gone (the icon uses `currentcolor`).
- **Tests.** The unit test for the upload button classes and one e2e selector (`button.btn` became `button.btn-solid`) were updated.

## Verification

- `yarn build` passes.
- `yarn test:unit` passes, 46/46.
- ESLint reports no new warnings. The only warning is the old unused `no-new` directive in `Info.vue`.
- A headless Chrome screenshot tour (Cypress) covered 10 routes at desktop (1440 px) and phone (390 px) width, light and dark, plus interactive states: popovers, error toast, upload validation, query results and the navbar drawer. It found no console errors from Bootstrap. The only warnings were Vue Router `next()` deprecations, which predate this work.
- Maven (`clean install` in `jena-fuseki-ui`): 14 of 15 e2e tests passed. The failure was the flaky upload test described below, not a Bootstrap issue.

## Regressions found with screenshots (all fixed)

1. **Upload: invalid graph name collapsed the input.** v6 removed `flex-wrap: wrap` from `.input-group`, so the `.invalid-feedback` inside the group squeezed the input to a few pixels. Fix: drop the unneeded `input-group` wrapper around the single input.
2. **Navbar icons sat above the text.** See alpha issue 1. Fix: `class="nav navbar-nav"`.
3. **YASR "Simple view" / "Ellipse" checkboxes became broken toggles.** YASR uses `class="switch"`, and v6 now styles `.switch` as its switch component. Fix: `.yasr .switch { all: revert; … }` in `Query.vue`.
4. **No space between the alert and the buttons in popovers.** v6 `.alert` has no bottom margin, where v5 had 1rem. Fix: `mb-5`.
5. **Dark mode turned on by itself.** v6 sets `color-scheme: light dark` on `:root`, so the UI followed the OS setting. Dark mode looked broken: the logo strokes were almost invisible, YASQE stayed white, and the CodeMirror gutter was half white. Fix: `<html data-bs-theme="light">` in `index.html`.

There is also a sixth, build-level fix. Vite 8's Lightning CSS minifier lowered all 83 `light-dark()` calls into a `--lightningcss-light/dark` polyfill, because Vite's default CSS target is below Bootstrap 6's browser floor. That polyfill ignores `data-bs-theme` (Bootstrap's own docs build hit the same problem in twbs/bootstrap#42471). Without a fix, the light pin would probably fail in production builds on dark-mode machines. Fix: `build.cssTarget: ['chrome130', 'edge130', 'firefox132', 'safari18']` in `vite.config.js`. The built CSS now keeps native `light-dark()`.

## Visual changes accepted as v6 design

- `theme-secondary` is lighter than v5 secondary. This shows on the version badge, the Clear button and the cancel buttons.
- Inactive card tabs are grey, not link-blue.
- The close button is a filled rounded square with the × cut out.
- Radios are larger, and checkboxes and radios use the primary accent colour.
- The brand text is slightly smaller.

## Feedback for the Bootstrap alpha

None of these had an issue in twbs/bootstrap on 2026-10-08. The issues and PRs searched cover everything since 2026-08 plus keyword searches. Related issues, both closed: #42930 (another undefined nav token) and #42471 (Lightning CSS lowering of `light-dark()`).

1. **`.navbar-nav` misses the nav link alignment tokens.**
   - In v6, `.nav-link` is `display: flex; align-items: var(--nav-link-align); justify-content: var(--nav-link-justify)`.
   - Those tokens are emitted only on `.nav`, and `$navbar-nav-tokens` does not define them.
   - A v5-style `<ul class="navbar-nav">` therefore falls back to `align-items: normal`, and an icon in a link sits above the text.
   - In v5, `.navbar-nav` was self-sufficient.
   - 12 of the 15 navbar examples in v6's own `navbar.mdx` use plain `navbar-nav`.
   - **Suggested change:**
     - Add `--nav-link-align` and `--nav-link-justify` to `$navbar-nav-tokens` (`scss/_navbar.scss`), or give `.nav-link` fallbacks such as `var(--nav-link-align, center)`. Either way, v5 markup keeps working.
     - Alternatively, if `.nav` is now required on `.navbar-nav`, say so in the migration guide and update the 12 docs examples.
2. **Tooltip and popover `placement: 'auto'` lost its meaning.**
   - `AttachmentMap.AUTO` maps to `'auto'`, which goes straight to Floating UI's `computePosition`.
   - Floating UI has no `'auto'` placement and needs the `autoPlacement` middleware, which Bootstrap never uses.
   - The coordinates fall to the default case, and `flip()` then resets to `top`.
   - Observed: v5 placed the Manage "remove" popover on the left (the side with the most room), and v6 places it on top.
   - **Suggested change:** in `_getFloatingMiddleware()` (`js/src/tooltip.ts`), use `autoPlacement()` instead of `flip()` when the placement is `'auto'`. Floating UI documents the two as mutually exclusive. Pass the starting placement as `top`. Add a unit test that `'auto'` picks the side with the most room. If `'auto'` is dropped instead, remove it from `AttachmentMap` and list it in the migration guide.
3. **Generic class names collide with third-party widgets.** The new `.switch` component restyles YASR's `class="switch"` checkboxes. Other new generic names (`.check`, `.radio`, `.menu`, `.dialog`, `.drawer`, `.chip`, `.avatar`, `.prose`) carry the same risk. Cascade layers do not help, because the third-party CSS sets only some of the properties.
   - **Suggested change:** scope component selectors to the markup they need. For example, style `.switch:has(> input[type="checkbox"])` rather than every `.switch`. At minimum, add a "class name collisions" note to the migration guide that lists the new generic names.
4. **Gaps in the migration guide.**
   - `.alert` lost its default `margin-bottom: 1rem`.
   - `.form-group` has styles again, but different ones. In v4 it only added `margin-bottom: 1rem`, and v5 removed it. v6 makes it a layout primitive (`display: grid; gap: .5rem`, no bottom margin). v4-era markup that did nothing in v5 now changes layout again; Fuseki has such markup in Upload and Query.
   - The guide tells projects to check browser support, but not to raise the bundler's CSS target. Without that, Vite 8 / Lightning CSS polyfills `light-dark()` and breaks `data-bs-theme`.
   - The navbar "After" example adds `.nav` to `.navbar-nav` without saying so (see item 1).
   - **Suggested change:** add these to `site/src/content/docs/guides/migration.mdx` and to the v5→v6 skill. The CSS target note should include a Vite example (`build.cssTarget: ['chrome130', 'edge130', 'firefox132', 'safari18']`) and refer to the reasoning in #42471.
5. **Self-compiled Sass and the bundled JS disagree on token names.** This comes from reading the `v6.0.0-alpha.1` source; it was not tested at runtime.
   - The Sass source writes tokens without a prefix. Only Bootstrap's own PostCSS build adds `--bs-`.
   - Some JS reads or writes the prefixed names: `range.ts` sets `--bs-range-fill`, but `_form-range.scss` reads `--range-fill`. `carousel.ts` uses `--bs-carousel-interval`, `--bs-carousel-items` and `--bs-carousel-items-peek`, and `nav-overflow.ts` reads `--bs-breakpoint-*`.
   - A project that compiles the Sass without the same PostCSS step would therefore get a range fill that never moves, the default carousel interval, and failed breakpoint lookups in nav overflow.
   - The skill says self-compiled tokens stay unprefixed, but not that this affects the JS.
   - **Suggested change:** document that Sass users who use these components must run `postcss-prefix-custom-properties` with the `bs-` prefix. Better, let the JS fall back to the unprefixed name when the prefixed one is empty.

## Notes for the real Jena upgrade (at v6 stable)

- Recheck each workaround above: the `.nav` class, the `.yasr .switch` revert, `mb-5` on alerts in popovers, the light pin and `cssTarget`. Drop each one that Bootstrap has fixed.
- Dark mode can be enabled when YASQE/YASR, CodeMirror 6 and the logo support it. Remove the `data-bs-theme="light"` pin, and keep `cssTarget` at Bootstrap's floor.
- Some markup has been dead since v5 and was left as it was: `text-right` (Info and Edit), `form-row`, `jumbotron`.
- The screenshot and video specs (`screenshots.cy.js`, `tour.cy.js`) lived only in a temporary scratch directory. They were run with `--spec` and `--config specPattern=…` against `yarn serve:offline`, with v5 exported via `git archive` for comparison. They could be added to the repo if this comparison should be repeatable.

## Upload bug found on the way

This bug is unrelated to Bootstrap. It is fixed on branch `jena-fuseki-ui-update-url-before-upload`, which is based on `main`.

- **Symptom 1.** The Maven e2e run failed on `upload.cy.js`, "accepts a blank graph name, and uploads to the dataset", with `POST 404 /`. The test failed 1 time in 8 locally on both v5 and v6.
- **Cause.** vue-upload-component copies `post-action` into each file when the file is added, and never updates it. `postActionUrl` is `''` until the dataset services have loaded. A file added before then posts to `/`.
- **Symptom 2.** The same mechanism makes a real user-facing bug. Select files first, then type a graph name, and the page shows `…/data?graph=…`, but the data is uploaded to the default graph.
- **Fix.** In `handleUploadWithErrorHandling`, call `component.update(file, { postAction: this.postActionUrl })` before `uploadHtml5`.
- **Regression test.** "uploads to the graph name entered after selecting files":
  - Without the fix, it failed 5 of 5 runs because the URL lacked `graph=`.
  - With the fix, the upload spec passed 8 of 8 runs (5/5 tests each).
  - The full e2e suite passed (16/16, 12 s), and the spec takes about 4 s for 5 tests (about 1 s more than before).
- **CI check.** Since the test was added (2026-07-28) there were 138 "Maven Build on PR" runs, and none failed on this test. For the 3 of 35 re-runs whose first-attempt logs were readable, the upload spec passed. Those first attempts failed on `TestFusekiServerBuild`, which looks like a separate flaky Java test.

## Environment notes

- Cypress 16.1.1 prints `spawn Unknown system error -86` on this arm64 Mac. Its bundled `node_modules/trash/lib/macos-trash` is x86_64-only and Rosetta is not installed, so old screenshots are not cleared before each run. This is harmless and does not change the exit code. To remove it, install Rosetta, or set `trashAssetsBeforeRuns: false`.

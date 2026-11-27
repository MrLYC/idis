import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const htmlPath = path.join(repoRoot, 'docs', 'index.html');
const nojekyllPath = path.join(repoRoot, 'docs', '.nojekyll');
const cargoTomlPath = path.join(repoRoot, 'Cargo.toml');

assert.ok(fs.existsSync(htmlPath), 'docs/index.html must exist');
assert.ok(fs.existsSync(nojekyllPath), 'docs/.nojekyll must exist');

const html = fs.readFileSync(htmlPath, 'utf8');
const cargoToml = fs.readFileSync(cargoTomlPath, 'utf8');
const versionMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
assert.ok(versionMatch, 'Cargo.toml must declare package version');
const pkgVersion = versionMatch[1];

function hexLuminance(hex) {
  const clean = hex.replace('#', '');
  const r = parseInt(clean.slice(0, 2), 16) / 255;
  const g = parseInt(clean.slice(2, 4), 16) / 255;
  const b = parseInt(clean.slice(4, 6), 16) / 255;
  const toLin = (c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
  return 0.2126 * toLin(r) + 0.7152 * toLin(g) + 0.0722 * toLin(b);
}

function contrastRatio(fgHex, bgHex) {
  const l1 = hexLuminance(fgHex);
  const l2 = hexLuminance(bgHex);
  const hi = Math.max(l1, l2);
  const lo = Math.min(l1, l2);
  return (hi + 0.05) / (lo + 0.05);
}

// ---------------------------------------------------------------------------
// 1. Self-contained zero-CDN & zero runtime network call gate
// ---------------------------------------------------------------------------
{
  const forbiddenExternal = [
    /<script[^>]+src=["'](?:https?:)?\/\//i,
    /<link[^>]+href=["'](?:https?:)?\/\//i,
    /<img[^>]+src=["'](?:https?:)?\/\//i,
    /@import\s+url\(\s*["']?(?:https?:)?\/\//i,
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bnew\s+WebSocket\s*\(/,
  ];
  for (const rx of forbiddenExternal) {
    assert.ok(!rx.test(html), `docs/index.html must not contain external/network load matching ${rx}`);
  }
  console.log('PASS [1/8]: Zero external CDN dependencies and zero runtime network calls');
}

// ---------------------------------------------------------------------------
// 2. Strict light-mode-only CSS, explicit color-scheme & WCAG AA contrast
// ---------------------------------------------------------------------------
{
  assert.ok(!/prefers-color-scheme\s*:\s*dark/i.test(html), 'must NOT include dark mode media query');
  assert.ok(!/data-theme\s*=\s*["']dark/i.test(html), 'must NOT include dark theme attribute');
  assert.ok(!/color-scheme\s*:\s*dark/i.test(html), 'must NOT set dark color-scheme');
  assert.ok(/<meta\s+name="color-scheme"\s+content="light">/i.test(html), 'must declare <meta name="color-scheme" content="light">');
  assert.ok(/color-scheme\s*:\s*light\s*;/i.test(html), 'must declare color-scheme: light in CSS');

  const tokens = {};
  for (const name of ['--bg-canvas', '--surface', '--surface-muted', '--ink-primary', '--ink-secondary', '--ink-muted', '--accent', '--warm', '--ok', '--warn', '--danger']) {
    const m = html.match(new RegExp(`${name}\\s*:\\s*(#[0-9a-fA-F]{6})`));
    assert.ok(m, `missing CSS token ${name}`);
    tokens[name] = m[1];
  }
  for (const surf of ['--bg-canvas', '--surface', '--surface-muted']) {
    const lum = hexLuminance(tokens[surf]);
    assert.ok(lum >= 0.70, `${surf} (${tokens[surf]}) luminance ${lum.toFixed(3)} must be >= 0.70`);
  }
  for (const ink of ['--ink-primary', '--ink-secondary', '--ink-muted', '--accent', '--warm', '--ok', '--warn', '--danger']) {
    for (const surf of ['--surface', '--surface-muted']) {
      const cr = contrastRatio(tokens[ink], tokens[surf]);
      assert.ok(cr >= 4.5, `${ink} (${tokens[ink]}) on ${surf} (${tokens[surf]}) contrast ${cr.toFixed(2)} < 4.5`);
    }
  }
  assert.ok(!/fill="#78716C"/i.test(html), 'SVG text must not use low-contrast #78716C');
  console.log('PASS [2/8]: Strict light-mode palette, color-scheme: light & WCAG AA contrast verified');
}

// ---------------------------------------------------------------------------
// 3. Non-developer readability, zero parenthetical bloat & zero source drawers
// ---------------------------------------------------------------------------
{
  assert.ok(!html.includes('tech-drawer'), 'docs/index.html must not contain developer source-code drawers');
  assert.ok(!/github\.com\/MrLYC\/idis\/blob\/main\/src\//.test(html), 'docs/index.html must not link raw Rust source files');

  const mainWithoutCode = html
    .replace(/<style>[\s\S]*?<\/style>/gi, '')
    .replace(/<script>[\s\S]*?<\/script>/gi, '');
  const visibleText = mainWithoutCode.replace(/<[^>]+>/g, ' ');
  const parens = visibleText.match(/[（(][^）)\n]{1,40}[）)]/g) || [];
  assert.deepEqual(parens, [], `visible main prose must avoid parenthetical bloat, found: ${parens.join(', ')}`);

  const forbiddenJargon = [
    'ScreenCaptureKit',
    'VideoToolbox',
    'x11grab',
    'ddagrab',
    'gdigrab',
    'WakePipe',
    'libFuzzer',
    'SIGKILL',
    'logind',
    '0.0.0.0:',
    '127.0.0.1:8787',
    'CSRF',
    'fsync',
    '4002',
    '--fps 60',
  ];
  for (const term of forbiddenJargon) {
    assert.ok(!html.includes(term), `non-developer showcase must not expose raw engineering jargon: ${term}`);
  }
  console.log('PASS [3/8]: Non-developer prose verified (0 parentheses, 0 source drawers, 0 raw jargon)');
}

// ---------------------------------------------------------------------------
// 4. Interactive SVG keyboard accessibility & ARIA structure gate
// ---------------------------------------------------------------------------
{
  for (const m of html.matchAll(/<g\b([^>]*)>/gi)) {
    const attrs = m[1];
    if (/cursor\s*:\s*pointer/i.test(attrs)) {
      assert.ok(/tabindex="0"/.test(attrs), `clickable SVG <g> missing tabindex="0": <g${attrs}>`);
      assert.ok(/role="button"/.test(attrs), `clickable SVG <g> missing role="button": <g${attrs}>`);
      assert.ok(/aria-label="[^"]+"/.test(attrs), `clickable SVG <g> missing aria-label: <g${attrs}>`);
    }
  }
  for (const m of html.matchAll(/<svg\b([^>]*)>([\s\S]*?)<\/svg>/gi)) {
    const svgAttrs = m[1];
    const body = m[2];
    if (/role="button"/.test(body)) {
      assert.ok(!/role="img"/.test(svgAttrs), 'interactive <svg> with role="button" children must use role="group", not role="img"');
    }
  }
  console.log('PASS [4/8]: All interactive SVG controls are keyboard-accessible and properly grouped');
}

// ---------------------------------------------------------------------------
// 5. Full DOM-aware Node VM simulation & interactive branch smoke test
// ---------------------------------------------------------------------------
{
  const scriptMatches = [...html.matchAll(/<script>([\s\S]*?)<\/script>/gi)];
  assert.equal(scriptMatches.length, 1, 'expected exactly 1 inline <script> block');
  const scriptCode = scriptMatches[0][1];
  new vm.Script(scriptCode, { filename: 'docs/index.html' });

  function parseAttrs(raw) {
    const map = new Map();
    for (const m of raw.matchAll(/([\w-]+)(?:="([^"]*)")?/g)) {
      map.set(m[1], m[2] === undefined ? '' : m[2]);
    }
    return map;
  }

  function makeEl(tag, rawAttrs = '') {
    const attrs = parseAttrs(rawAttrs);
    const listeners = new Map();
    const classSet = new Set((attrs.get('class') || '').split(/\s+/).filter(Boolean));
    const el = {
      tagName: tag.toUpperCase(),
      id: attrs.get('id') || '',
      style: {},
      textContent: '',
      innerHTML: '',
      value: attrs.get('value') || '0',
      disabled: attrs.has('disabled'),
      firstChild: null,
      children: [],
      parent: null,
      classList: {
        add: (...cls) => cls.forEach((c) => classSet.add(c)),
        remove: (...cls) => cls.forEach((c) => classSet.delete(c)),
        toggle: (c, force) => {
          if (force === undefined) {
            if (classSet.has(c)) classSet.delete(c);
            else classSet.add(c);
          } else if (force) classSet.add(c);
          else classSet.delete(c);
        },
        contains: (c) => classSet.has(c),
      },
      set className(v) {
        classSet.clear();
        String(v).split(/\s+/).filter(Boolean).forEach((c) => classSet.add(c));
      },
      get className() {
        return [...classSet].join(' ');
      },
      setAttribute(k, v) {
        attrs.set(k, String(v));
      },
      getAttribute(k) {
        return attrs.has(k) ? attrs.get(k) : null;
      },
      removeAttribute(k) {
        attrs.delete(k);
      },
      getBoundingClientRect() {
        return { width: 100, height: 100 };
      },
      appendChild(child) {
        child.parent = this;
        this.children.push(child);
        this.firstChild = this.children[0] || null;
        return child;
      },
      removeChild(child) {
        const idx = this.children.indexOf(child);
        if (idx >= 0) this.children.splice(idx, 1);
        this.firstChild = this.children[0] || null;
        return child;
      },
      querySelector(sel) {
        if (sel.startsWith('.')) {
          const cls = sel.slice(1);
          const queue = [...this.children];
          while (queue.length) {
            const cur = queue.shift();
            if (cur.classList.contains(cls)) return cur;
            queue.push(...cur.children);
          }
        }
        return null;
      },
      addEventListener(ev, fn) {
        if (!listeners.has(ev)) listeners.set(ev, []);
        listeners.get(ev).push(fn);
      },
      dispatch(ev, payload = {}) {
        for (const fn of listeners.get(ev) || []) {
          fn({ target: this, preventDefault() {}, ...payload });
        }
      },
      click() {
        this.dispatch('click');
      },
    };
    return el;
  }

  // Lightweight tag parser capturing ancestor stack so real querySelectorAll selectors match!
  const allElements = [];
  const byIdMap = new Map();
  const stack = [];
  const voidTags = new Set(['meta', 'input', 'line', 'rect', 'circle', 'polygon', 'polyline', 'path', 'stop', 'br', 'hr']);
  const bodyHtml = html.replace(/<style>[\s\S]*?<\/style>/gi, '').replace(/<script>[\s\S]*?<\/script>/gi, '');
  for (const m of bodyHtml.matchAll(/<(\/?)([a-zA-Z][\w-]*)([^>]*)>/g)) {
    const isClose = m[1] === '/';
    const tag = m[2].toLowerCase();
    const rawAttrs = m[3] || '';
    const selfClosing = rawAttrs.trim().endsWith('/') || voidTags.has(tag);
    if (isClose) {
      while (stack.length && stack[stack.length - 1].tagName.toLowerCase() !== tag) {
        stack.pop();
      }
      stack.pop();
      continue;
    }
    const el = makeEl(tag, rawAttrs);
    if (stack.length) {
      stack[stack.length - 1].appendChild(el);
    }
    allElements.push(el);
    if (el.id) byIdMap.set(el.id, el);
    if (!selfClosing) stack.push(el);
  }

  function matchesSimple(el, part) {
    const attrM = part.match(/^([a-z]*)?\[([\w-]+)(?:="([^"]*)")?\]$/);
    if (attrM) {
      if (attrM[1] && el.tagName.toLowerCase() !== attrM[1]) return false;
      const val = el.getAttribute(attrM[2]);
      if (val === null) return false;
      if (attrM[3] !== undefined && val !== attrM[3]) return false;
      return true;
    }
    if (part.startsWith('#')) return el.id === part.slice(1);
    if (part.startsWith('.')) return el.classList.contains(part.slice(1));
    return el.tagName.toLowerCase() === part.toLowerCase();
  }

  function hasAncestor(el, part) {
    let cur = el.parent;
    while (cur) {
      if (matchesSimple(cur, part)) return true;
      cur = cur.parent;
    }
    return false;
  }

  function querySelectorAll(selector) {
    const parts = selector.trim().split(/\s+/);
    const leaf = parts[parts.length - 1];
    const ancestors = parts.slice(0, -1);
    return allElements.filter((el) => {
      if (!matchesSimple(el, leaf)) return false;
      return ancestors.every((anc) => hasAncestor(el, anc));
    });
  }

  const sandbox = {
    window: {
      innerHeight: 900,
      scrollY: 0,
      addEventListener() {},
      matchMedia: () => ({ matches: true }),
    },
    document: {
      documentElement: { scrollHeight: 4000 },
      getElementById: (id) => byIdMap.get(id) || null,
      querySelectorAll,
      createElement: (tag) => makeEl(tag),
      createElementNS: (_ns, tag) => makeEl(tag),
    },
    console,
    Math,
    JSON,
    parseInt,
    String,
    setInterval: () => 1,
    clearInterval: () => {},
    setTimeout: () => 1,
    clearTimeout: () => {},
  };
  vm.createContext(sandbox);
  vm.runInContext(scriptCode, sandbox);

  const sim = sandbox.window.IdisSim;
  assert.ok(sim, 'window.IdisSim must be exposed');

  // ABR 5-tier ladder & PSM guard
  assert.equal(sim.ABR_LADDER.length, 5);
  assert.deepEqual(Array.from(sim.ABR_LADDER, (t) => t.scalePct), [100, 100, 100, 100, 100]);
  assert.deepEqual(Array.from(sim.ABR_LADDER, (t) => t.bitratePct), [100, 65, 40, 25, 15]);
  assert.deepEqual(Array.from(sim.ABR_LADDER, (t) => t.fpsPct), [100, 100, 75, 60, 50]);
  assert.equal(sim.computeAbrStep(220, 0, true).tier, 0, 'Wi-Fi PSM high RTT w/ 0 loss must NOT downgrade');
  assert.equal(sim.computeAbrStep(220, 9, false).tier, 4, 'severe congestion must step down to Tier 4');

  // InFlight bounds
  assert.ok(sim.computeInFlight(15, 0, true, false) <= 2, 'USB InFlight max bound is 2');
  assert.ok(sim.computeInFlight(15, 0, false, false) <= 4, 'Wi-Fi InFlight max bound is 4');
  assert.equal(sim.computeInFlight(220, 8, false, false), 1, 'severe congestion shrinks InFlight to floor 1');

  // P2P tree topology, exact savings formula & ZERO edge-vs-node collisions for n=1..8
  for (const enabled of [false, true]) {
    for (let n = 1; n <= 8; n++) {
      const tree = sim.computeP2pTree(n, enabled);
      if (enabled && n >= 2) {
        assert.equal(tree.directViewers, 1);
        assert.equal(tree.savedPct, Math.floor(((n - 1) * 100) / n));
      } else {
        assert.equal(tree.savedPct, 0);
      }
      const layout = sim.computeP2pLayout(tree);
      const halfW = layout.nodeW / 2;
      const halfH = layout.nodeH / 2;
      // Check pairwise non-overlap of viewer nodes
      for (let i = 0; i < tree.nodes.length; i++) {
        const a = layout.positions[tree.nodes[i].id];
        for (let j = i + 1; j < tree.nodes.length; j++) {
          const b = layout.positions[tree.nodes[j].id];
          const overlapX = Math.abs(a.x - b.x) < layout.nodeW;
          const overlapY = Math.abs(a.y - b.y) < layout.nodeH;
          assert.ok(!(overlapX && overlapY), `P2P nodes #${i + 1} and #${j + 1} overlap (enabled=${enabled}, n=${n})`);
        }
      }
      // Check direct edges never cut through any other viewer box
      for (const nd of tree.nodes) {
        const from = layout.positions[nd.parent];
        const to = layout.positions[nd.id];
        const x1 = from.x + halfW;
        const y1 = from.y;
        const x2 = to.x - halfW;
        const y2 = to.y;
        for (const other of tree.nodes) {
          if (other.id === nd.id || other.id === nd.parent) continue;
          const o = layout.positions[other.id];
          if (o.x - halfW > Math.min(x1, x2) && o.x + halfW < Math.max(x1, x2)) {
            const t = (o.x - x1) / (x2 - x1);
            const yAtX = y1 + t * (y2 - y1);
            assert.ok(
              Math.abs(yAtX - o.y) > halfH,
              `P2P edge ${nd.parent}->${nd.id} slices through node #${other.id} (enabled=${enabled}, n=${n})`,
            );
          }
        }
      }
    }
  }

  // Port isolation oracle
  assert.equal(sim.checkPortIsolation('admin', 'settings').allowed, true);
  assert.equal(sim.checkPortIsolation('admin', 'watch').allowed, false);
  assert.equal(sim.checkPortIsolation('viewer', 'watch').allowed, true);
  assert.equal(sim.checkPortIsolation('viewer', 'settings').allowed, false);

  // Workflow scenario accuracy: ONLY browser mode uses QR scanning
  assert.equal(sim.getWorkflowScenario('web').usesQr, true);
  for (const nonQr of ['usb', 'wifi', 'virtual']) {
    const sc = sim.getWorkflowScenario(nonQr);
    assert.equal(sc.usesQr, false, `${nonQr} must NOT show QR`);
    for (const st of sc.steps) {
      assert.ok(!st.title.includes('扫码') && !st.title.includes('二维码'), `${nonQr} must not ask to scan QR`);
    }
  }

  // Exercise REAL click & keyboard handlers across ALL 7 chapters!
  byIdMap.get('hero-move-btn').click();
  assert.equal(byIdMap.get('hero-move-btn').getAttribute('aria-pressed'), 'true');

  // Ch 1: switch to USB -> QR hidden, alt badge shown
  querySelectorAll('#wf-scenario-chips .chip').find((c) => c.getAttribute('data-wf-scene') === 'usb').click();
  assert.equal(byIdMap.get('wf-qr-group').getAttribute('display'), 'none');
  assert.equal(byIdMap.get('wf-alt-badge').getAttribute('display'), 'inline');
  byIdMap.get('wf-next-btn').click();

  // Ch 2: eco preset MUST enable lowPower; share preset disables lowPower; dragback disabled initially
  assert.equal(byIdMap.get('feat-btn-dragback').disabled, true);
  querySelectorAll('#feat-preset-chips .chip').find((c) => c.getAttribute('data-preset') === 'eco').click();
  assert.equal(byIdMap.get('feat-btn-lowpower').getAttribute('aria-pressed'), 'true', 'eco preset must activate lowPower');
  querySelectorAll('#feat-preset-chips .chip').find((c) => c.getAttribute('data-preset') === 'share').click();
  assert.equal(byIdMap.get('feat-btn-lowpower').getAttribute('aria-pressed'), 'false', 'share preset must deactivate lowPower');
  byIdMap.get('feat-btn-popup').click();
  assert.equal(byIdMap.get('feat-btn-dragback').disabled, false);
  byIdMap.get('feat-viewer-click').dispatch('keydown', { key: 'Enter' });

  // Ch 2b: v0.3.8 4-zone iPad edge gesture playground
  querySelectorAll('.gest-zone').find((g) => g.getAttribute('data-gest-zone') === 'rb').dispatch('keydown', { key: 'Enter' });
  querySelectorAll('#gest-action-chips .chip').find((c) => c.getAttribute('data-gest-act') === 'hotkey').click();
  assert.equal(byIdMap.get('gest-lbl-rb').textContent, '热键');
  assert.ok(byIdMap.get('gest-feedback-title').textContent.includes('右下边缘向左滑'));

  // Ch 3: disable gate + drop -> glitch preview visible; re-enable gate -> clean preview visible
  byIdMap.get('pipe-gate-btn').click();
  byIdMap.get('pipe-drop-btn').click();
  assert.equal(byIdMap.get('pipe-preview-glitch').getAttribute('display'), 'inline');
  byIdMap.get('pipe-gate-btn').click();
  assert.equal(byIdMap.get('pipe-preview-clean').getAttribute('display'), 'inline');
  querySelectorAll('.pipe-node')[2].dispatch('keydown', { key: ' ' });

  // Ch 4: path trace numbers modules; clicking standalone module clears active path chip
  querySelectorAll('#arch-path-chips .chip').find((c) => c.getAttribute('data-arch-path') === 'lock').click();
  assert.ok(querySelectorAll('#arch-layers .arch-mod').some((m) => m.textContent.startsWith('1. ')));
  querySelectorAll('#arch-layers .arch-mod')[0].click();
  assert.ok(querySelectorAll('#arch-path-chips .chip').every((c) => !c.classList.contains('active')));
  byIdMap.get('guard-sleep-btn').click();
  assert.equal(byIdMap.get('guard-sleep-btn').getAttribute('aria-pressed'), 'true');
  byIdMap.get('guard-sleep-btn').click();
  assert.equal(byIdMap.get('guard-sleep-btn').getAttribute('aria-pressed'), 'false');

  // Ch 5: clicking cafe preset visibly shifts multiple chart points (not flat 100%)
  querySelectorAll('#net-presets .chip').find((c) => c.getAttribute('data-net-preset') === 'cafe').click();
  const pts = byIdMap.get('net-bitrate-line').getAttribute('points').split(' ');
  const droppedPts = pts.filter((p) => parseFloat(p.split(',')[1]) > 80);
  assert.ok(droppedPts.length >= 5, `cafe preset must visibly shift >=5 chart points, got ${droppedPts.length}`);

  // Ch 6: click pyramid & chaos buttons, assert no doubled prefix
  querySelectorAll('.pyr-layer')[2].dispatch('keydown', { key: 'Enter' });
  for (const btn of querySelectorAll('#chaos-buttons button')) {
    btn.click();
    const rep = byIdMap.get('chaos-report').innerHTML;
    assert.ok(!/<strong>([^<]+)：<\/strong>\1/.test(rep), `doubled title prefix in chaos report: ${rep}`);
  }

  // Ch 7: all 3 models work, render Chinese KV rows (no JSON braces), and Model 3 preset violates in bug mode
  byIdMap.get('tla-bug-toggle').click();
  assert.equal(byIdMap.get('tla-verdict-pill').textContent, '拦截到红线违规反例');
  for (const tabKey of ['video', 'config']) {
    querySelectorAll('#tla-model-tabs .chip').find((c) => c.getAttribute('data-tla-model') === tabKey).click();
    assert.equal(byIdMap.get('tla-verdict-pill').textContent, '拦截到红线违规反例', `${tabKey} must show violation in bug mode`);
  }
  const tlaKv = byIdMap.get('tla-state-view');
  assert.ok(tlaKv.children.length >= 5, 'tla-state-view must render Chinese KV rows');
  assert.ok(!tlaKv.textContent.includes('{'), 'tla-state-view must not dump raw JSON');
  // Trigger preset-switch violation specifically in config model
  byIdMap.get('tla-reset-btn').click();
  assert.equal(byIdMap.get('tla-verdict-pill').textContent, '全部安全红线通过');

  console.log('PASS [5/8]: Full DOM VM smoke test, ABR/InFlight/P2P geometry & all 7 chapters verified');
}

// ---------------------------------------------------------------------------
// 6. ABR Y-axis linear gridline alignment check
// ---------------------------------------------------------------------------
{
  assert.ok(html.includes('y1="30" x2="400" y2="30"'), '100% gridline must sit at y=30');
  assert.ok(html.includes('y1="80" x2="400" y2="80"'), '60% gridline must sit at y=80');
  assert.ok(html.includes('y1="130" x2="400" y2="130"'), '20% gridline must sit at y=130');
  assert.ok(html.includes('y1="155" x2="400" y2="155"'), '0% baseline must sit at y=155');
  console.log('PASS [6/8]: ABR chart Y-axis gridlines mathematically aligned with curve formula');
}

// ---------------------------------------------------------------------------
// 7. DOM ID, anchor & duplicate ID integrity
// ---------------------------------------------------------------------------
{
  const seen = new Set();
  const dupes = [];
  for (const m of html.matchAll(/\bid="([^"]+)"/g)) {
    const id = m[1];
    if (seen.has(id)) dupes.push(id);
    seen.add(id);
  }
  assert.deepEqual(dupes, [], `duplicate DOM IDs found: ${dupes.join(', ')}`);

  for (const m of html.matchAll(/href="#([^"]+)"/g)) {
    const target = m[1];
    assert.ok(seen.has(target), `broken internal anchor href="#${target}"`);
  }

  const scriptCode = html.match(/<script>([\s\S]*?)<\/script>/i)[1];
  for (const m of scriptCode.matchAll(/\bbyId\("([^"]+)"\)/g)) {
    const id = m[1];
    assert.ok(seen.has(id), `script references missing element id="${id}"`);
  }

  for (const ch of ['workflow', 'features', 'principles', 'architecture', 'network', 'testing', 'formal']) {
    assert.ok(seen.has(ch), `missing required chapter anchor #${ch}`);
  }
  console.log(`PASS [7/8]: DOM ID integrity verified (${seen.size} unique IDs, 0 broken anchors)`);
}

// ---------------------------------------------------------------------------
// 8. Zero PII, verified GitHub guide links & ground-truth metrics sync
// ---------------------------------------------------------------------------
{
  for (const forbidden of [/\/Users\//, /\/home\//, /\/media\//, /C:\\Users\\/i]) {
    assert.ok(!forbidden.test(html), `docs/index.html must not contain local filesystem path matching ${forbidden}`);
  }
  assert.ok(
    !/href="(?!https?:\/\/)(?!#)[^"]+\.md(?:#[^"]*)?"/i.test(html),
    'docs/index.html must not use relative .md links',
  );

  let blobCount = 0;
  for (const m of html.matchAll(/https:\/\/github\.com\/MrLYC\/idis\/blob\/main\/([^"'\s#<]+)/g)) {
    const rel = m[1];
    const abs = path.join(repoRoot, rel);
    assert.ok(fs.existsSync(abs), `GitHub link points to non-existent repo path: ${rel}`);
    blobCount += 1;
  }
  assert.ok(blobCount >= 2, `expected verified GitHub guide/policy links, found ${blobCount}`);

  assert.ok(html.includes(`v${pkgVersion}`), `docs/index.html must match Cargo.toml version v${pkgVersion}`);
  assert.ok(html.includes('35,196'), 'docs/index.html must cite verified formal verification total 35,196');
  assert.ok(html.includes('13,468'), 'docs/index.html must cite lock model states 13,468');
  assert.ok(html.includes('21,448'), 'docs/index.html must cite video model states 21,448');
  console.log(`PASS [8/8]: Zero PII, ${blobCount} guide links, version (v${pkgVersion}) & verified metrics match repo`);
}

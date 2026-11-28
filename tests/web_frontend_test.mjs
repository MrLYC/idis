#!/usr/bin/env node
// Zero-dependency behavioral test harness for src/web/admin.html and src/web/viewer.html.
// Runs extracted <script> blocks inside isolated Node vm contexts with lightweight DOM,
// fetch, WebSocket, and MediaSource mocks so real frontend state-machine bugs are caught in CI.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const repoRoot = process.cwd();
const adminHtml = fs.readFileSync(path.join(repoRoot, 'src/web/admin.html'), 'utf8');
const viewerHtml = fs.readFileSync(path.join(repoRoot, 'src/web/viewer.html'), 'utf8');

function extractScripts(html) {
  return [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
}

function extractElementIds(html) {
  const ids = new Set();
  for (const m of html.matchAll(/\bid="([^"]+)"/g)) {
    ids.add(m[1]);
  }
  return ids;
}

function makeMockElement(id = '') {
  const classes = new Set();
  const attrs = new Map();
  const listeners = new Map();
  return {
    id,
    tagName: 'DIV',
    value: '',
    checked: false,
    disabled: false,
    textContent: '',
    innerHTML: '',
    src: '',
    style: {},
    dataset: {},
    clientWidth: 1280,
    clientHeight: 720,
    videoWidth: 1280,
    videoHeight: 720,
    readyState: 4,
    buffered: { length: 0, start: () => 0, end: () => 0 },
    currentTime: 0,
    paused: false,
    classList: {
      add: (...cs) => cs.forEach((c) => classes.add(c)),
      remove: (...cs) => cs.forEach((c) => classes.delete(c)),
      toggle: (c, force) => {
        if (force === undefined) {
          if (classes.has(c)) classes.delete(c);
          else classes.add(c);
        } else if (force) classes.add(c);
        else classes.delete(c);
      },
      contains: (c) => classes.has(c),
    },
    setAttribute: (k, v) => attrs.set(k, String(v)),
    getAttribute: (k) => attrs.get(k) ?? null,
    removeAttribute: (k) => attrs.delete(k),
    addEventListener: (ev, fn) => {
      if (!listeners.has(ev)) listeners.set(ev, []);
      listeners.get(ev).push(fn);
    },
    removeEventListener: () => {},
    querySelector: () => null,
    querySelectorAll: () => [],
    closest: () => null,
    children: [],
    firstChild: null,
    appendChild: (c) => c,
    removeChild: (c) => c,
    focus: () => {},
    play: () => Promise.resolve(),
    pause: () => {},
    scrollIntoView: () => {},
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 1280, height: 720 }),
    _classes: classes,
    _listeners: listeners,
  };
}

function createDomEnv(html, { fetchImpl, wsHook } = {}) {
  const htmlIds = extractElementIds(html);
  const elements = new Map();
  for (const id of htmlIds) {
    elements.set(id, makeMockElement(id));
  }
  const docListeners = new Map();
  const winListeners = new Map();
  const timers = [];
  const wsInstances = [];
  const sourceBuffers = [];

  class MockWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url) {
      this.url = url;
      this.readyState = 1;
      this.binaryType = 'blob';
      this.sent = [];
      wsInstances.push(this);
      if (wsHook) wsHook(this);
    }
    send(d) {
      this.sent.push(d);
    }
    close(code = 1000) {
      this.readyState = 3;
      if (this.onclose) this.onclose({ code });
    }
  }

  class MockSourceBuffer {
    constructor() {
      this.updating = false;
      this.appended = [];
      this.listeners = new Map();
      this.buffered = { length: 0, start: () => 0, end: () => 0 };
    }
    addEventListener(ev, fn) {
      if (!this.listeners.has(ev)) this.listeners.set(ev, []);
      this.listeners.get(ev).push(fn);
    }
    appendBuffer(buf) {
      this.appended.push(new Uint8Array(buf));
      const fns = this.listeners.get('updateend') || [];
      fns.forEach((f) => f());
    }
    remove() {}
  }

  class MockMediaSource {
    static isTypeSupported() {
      return true;
    }
    constructor() {
      this.readyState = 'open';
      this.sourceBuffers = [];
      this.listeners = new Map();
    }
    addEventListener(ev, fn) {
      if (!this.listeners.has(ev)) this.listeners.set(ev, []);
      this.listeners.get(ev).push(fn);
      if (ev === 'sourceopen') fn();
    }
    addSourceBuffer() {
      const sb = new MockSourceBuffer();
      this.sourceBuffers.push(sb);
      sourceBuffers.push(sb);
      return sb;
    }
  }

  const document = {
    hidden: false,
    visibilityState: 'visible',
    fullscreenElement: null,
    webkitFullscreenElement: null,
    body: makeMockElement('body'),
    documentElement: makeMockElement('html'),
    getElementById: (id) => {
      if (!elements.has(id)) {
        elements.set(id, makeMockElement(id));
      }
      return elements.get(id);
    },
    querySelector: () => null,
    querySelectorAll: () => [],
    createElement: (tag) => {
      const el = makeMockElement('');
      el.tagName = tag.toUpperCase();
      return el;
    },
    addEventListener: (ev, fn) => {
      if (!docListeners.has(ev)) docListeners.set(ev, []);
      docListeners.get(ev).push(fn);
    },
    exitFullscreen: () => Promise.resolve(),
  };

  const storage = new Map();
  const sandbox = {
    console,
    Math,
    Date,
    JSON,
    Map,
    Set,
    Array,
    Object,
    String,
    Number,
    Boolean,
    Promise,
    Uint8Array,
    DataView,
    ArrayBuffer,
    TextDecoder,
    TextEncoder,
    AbortController,
    URLSearchParams,
    btoa,
    atob,
    encodeURIComponent,
    decodeURIComponent,
    parseInt,
    parseFloat,
    isNaN,
    isFinite,
    document,
    location: {
      protocol: 'http:',
      host: '127.0.0.1:8787',
      pathname: '/',
      search: '',
      href: 'http://127.0.0.1:8787/',
    },
    history: { replaceState: () => {} },
    navigator: {
      clipboard: { writeText: () => Promise.resolve() },
      userAgent: 'Mozilla/5.0 Chrome/130.0.0.0',
    },
    localStorage: {
      getItem: (k) => storage.get(k) ?? null,
      setItem: (k, v) => storage.set(k, String(v)),
      removeItem: (k) => storage.delete(k),
    },
    URL: {
      createObjectURL: () => 'blob:mock-url',
      revokeObjectURL: () => {},
    },
    Blob: class MockBlob {},
    WebSocket: MockWebSocket,
    MediaSource: MockMediaSource,
    RTCPeerConnection: undefined,
    fetch: fetchImpl || (async () => ({ ok: true, status: 200, json: async () => ({}) })),
    setTimeout: (fn, ms) => {
      const id = timers.length + 1;
      timers.push({ id, fn, ms, cleared: false });
      return id;
    },
    clearTimeout: (id) => {
      const t = timers.find((x) => x.id === id);
      if (t) t.cleared = true;
    },
    setInterval: (fn, ms) => {
      const id = timers.length + 1;
      timers.push({ id, fn, ms, cleared: false, interval: true });
      return id;
    },
    clearInterval: (id) => {
      const t = timers.find((x) => x.id === id);
      if (t) t.cleared = true;
    },
    requestAnimationFrame: (fn) => fn(),
    addEventListener: (ev, fn) => {
      if (!winListeners.has(ev)) winListeners.set(ev, []);
      winListeners.get(ev).push(fn);
    },
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;

  const ctx = vm.createContext(sandbox);
  for (const script of extractScripts(html)) {
    vm.runInContext(script, ctx);
  }
  return { ctx, elements, htmlIds, docListeners, winListeners, wsInstances, sourceBuffers, timers };
}

// =========================================================================
// 1. Static DOM ID & Inline Handler Reference Integrity (Both HTML Files)
// =========================================================================
for (const [name, html] of [
  ['admin.html', adminHtml],
  ['viewer.html', viewerHtml],
]) {
  const ids = extractElementIds(html);
  const scripts = extractScripts(html).join('\n');
  const missingIds = [];
  for (const m of scripts.matchAll(/getElementById\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    if (!ids.has(m[1])) missingIds.push(m[1]);
  }
  assert.deepEqual(missingIds, [], `${name} references missing DOM IDs: ${missingIds.join(', ')}`);

  // Verify every inline onclick="fn(...)" / onchange="fn(...)" references a defined function
  const env = createDomEnv(html, {
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ admin_logged_in: false, viewer_logged_in: false, viewer_enabled: false }),
    }),
  });
  const missingFns = [];
  for (const m of html.matchAll(/\bon(?:click|change|input|submit)="([a-zA-Z_$][\w$]*)\s*\(/g)) {
    const fnName = m[1];
    if (typeof env.ctx[fnName] !== 'function') missingFns.push(fnName);
  }
  assert.deepEqual(missingFns, [], `${name} inline handlers reference undefined fns: ${missingFns.join(', ')}`);
}
console.log('PASS [1/5]: Static DOM ID & inline handler integrity (admin.html + viewer.html)');

// =========================================================================
// 2. viewer.html Behavioral Tests (BUG-C5, MSE DPB gate, visibility, keydown)
// =========================================================================
{
  let authReply = {
    admin_logged_in: false,
    viewer_logged_in: true,
    viewer_enabled: true,
    web_require_approval: true,
    viewer_approved: true,
    viewer_fingerprint: 'fp:11223344556677889900aabb',
    viewer_label: 'Chrome / macOS',
    max_web_viewers: 2,
    active_web_viewers: 0,
    max_screen_connections: 1,
    total_screen_connections: 1,
    web_screen_mode: 'main',
    supports_independent_web_screen: true,
  };
  const env = createDomEnv(viewerHtml, {
    fetchImpl: async (url) => {
      if (url === '/api/auth/status') {
        return { ok: true, status: 200, json: async () => authReply };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });

  // Start stream -> receive init JSON -> P-frame BEFORE IDR must be dropped (VID-1)!
  await env.ctx.checkAuth();
  assert.equal(env.wsInstances.length >= 1, true, 'approved viewer must open WebSocket');
  const activeWs = env.wsInstances[env.wsInstances.length - 1];
  activeWs.onmessage({
    data: JSON.stringify({
      type: 'init',
      codec: 'avc1.42c01e',
      width: 1280,
      height: 720,
      source: 'main',
      reset: true,
    }),
  });
  // Verify main-screen source badge renders correctly
  assert.ok(
    env.elements.get('streamSourceBadge').textContent.includes('电脑主屏幕'),
    'source=main must display 电脑主屏幕 badge'
  );

  // Inject fMP4 init segment (kind=0x01), then P-frame (kind=0x03) BEFORE any IDR (kind=0x02)
  activeWs.onmessage({ data: new Uint8Array([0x01, 0, 0, 0, 1, 0x66, 0x74, 0x79, 0x70]).buffer });
  const sb = env.sourceBuffers[env.sourceBuffers.length - 1];
  assert.ok(sb, 'SourceBuffer must be created on init');
  const beforeCount = sb.appended.length;
  activeWs.onmessage({ data: new Uint8Array([0x03, 0, 0, 0, 1, 0x6d, 0x6f, 0x6f, 0x66]).buffer });
  assert.equal(sb.appended.length, beforeCount, 'MSE gate must drop P-frame (kind=3) while awaiting IDR');

  // Now inject IDR (kind=0x02) -> MUST be appended, then subsequent P-frame MUST pass
  activeWs.onmessage({ data: new Uint8Array([0x02, 0, 0, 0, 1, 0x6d, 0x6f, 0x6f, 0x66]).buffer });
  activeWs.onmessage({ data: new Uint8Array([0x03, 0, 0, 0, 2, 0x6d, 0x6f, 0x6f, 0x66]).buffer });
  assert.equal(sb.appended.length, beforeCount + 2, 'IDR and following P-frame must append cleanly');

  // BUG-C5 regression: Admin revokes viewer -> WS closes with 4001 -> checkAuth() transitions to #secViewApproval!
  authReply = { ...authReply, viewer_approved: false };
  await activeWs.onclose({ code: 4001 });
  // Let async checkAuth settle
  await new Promise((r) => setImmediate(r));
  assert.equal(
    env.elements.get('secViewApproval').classList.contains('hidden'),
    false,
    '4001 close when viewer_approved=false must show #secViewApproval'
  );
  assert.equal(
    env.elements.get('secViewStage').classList.contains('hidden'),
    true,
    '4001 close when viewer_approved=false must hide #secViewStage'
  );

  // BUG-C5 regression: keydown 'f' while #secViewApproval is visible must NOT enter fullscreen
  let defaultPrevented = false;
  for (const fn of env.docListeners.get('keydown') || []) {
    fn({ key: 'f', target: { tagName: 'BODY' }, preventDefault: () => { defaultPrevented = true; } });
  }
  assert.equal(defaultPrevented, false, 'F shortcut must be ignored while approval screen is shown');

  // BUG-C5 regression: !gotFrame when max_screen_connections=1, total_screen_connections=1,
  // max_web_viewers=2, active_web_viewers=1 MUST NOT show false "扩展屏连接数已满"!
  authReply = {
    ...authReply,
    viewer_approved: true,
    max_web_viewers: 2,
    active_web_viewers: 1,
    max_screen_connections: 1,
    total_screen_connections: 1,
  };
  await env.ctx.checkAuth();
  const ws2 = env.wsInstances[env.wsInstances.length - 1];
  await ws2.onclose({ code: 1006 });
  await new Promise((r) => setImmediate(r));
  // BUG-C2-1 regression: Admin kicks an STILL-APPROVED viewer with 4001 -> must NOT auto-reconnect!
  authReply = { ...authReply, viewer_logged_in: true, viewer_approved: true, max_web_viewers: 2 };
  await env.ctx.checkAuth();
  const wsBeforeKick = env.wsInstances.length;
  const wsKicked = env.wsInstances[env.wsInstances.length - 1];
  await wsKicked.onclose({ code: 4001 });
  await new Promise((r) => setImmediate(r));
  assert.equal(
    env.wsInstances.length,
    wsBeforeKick,
    'BUG-C2-1 regression: 4001 kick on valid session must NOT auto-reconnect'
  );
  assert.ok(
    env.elements.get('streamStatus').textContent.includes('已被管理员断开'),
    'kicked viewer must see admin-disconnected status'
  );

  // P2-C3 regression: After 4001 admin kick (manualReconnectRequired=true), tab-switch / online
  // events (onViewerForegroundOrOnline) MUST NOT auto-reconnect! Only explicit reconnectStream() clears it.
  const wsAfterKick = env.wsInstances.length;
  env.ctx.onViewerForegroundOrOnline();
  await new Promise((r) => setImmediate(r));
  assert.equal(
    env.wsInstances.length,
    wsAfterKick,
    'P2-C3 regression: tab-switch foreground event must NOT auto-reconnect an admin-kicked viewer'
  );
  env.ctx.reconnectStream();
  await new Promise((r) => setImmediate(r));
  assert.equal(
    env.wsInstances.length,
    wsAfterKick + 1,
    'explicit reconnectStream() must clear manualReconnectRequired latch and reconnect'
  );

  // P2-C5 regression: Pending mseRecoverTimer MUST be cancelled by terminal 4001/4002 close
  // and must NEVER override manualReconnectRequired!
  const envMseKick = createDomEnv(viewerHtml, {
    fetchImpl: async (url) => {
      if (url === '/api/auth/status') {
        return { ok: true, status: 200, json: async () => ({ ...authReply, viewer_logged_in: true, viewer_approved: true }) };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await envMseKick.ctx.checkAuth();
  const wsMse = envMseKick.wsInstances[envMseKick.wsInstances.length - 1];
  const timersBeforeMse = envMseKick.timers.length;
  envMseKick.ctx.tryRecoverMediaSource('test-err');
  const recoverTimer = envMseKick.timers.slice(timersBeforeMse).find((t) => !t.cleared && !t.interval);
  assert.ok(recoverTimer, 'tryRecoverMediaSource must arm mseRecoverTimer');
  const wsCountBefore4002 = envMseKick.wsInstances.length;
  await wsMse.onclose({ code: 4002 });
  assert.equal(recoverTimer.cleared, true, 'P2-C5: 4002 lock close must cancel pending mseRecoverTimer');
  // Even if callback somehow fires late, manualReconnectRequired guard must prevent reconnect
  recoverTimer.fn();
  await new Promise((r) => setImmediate(r));
  assert.equal(envMseKick.wsInstances.length, wsCountBefore4002, 'P2-C5: late mseRecoverTimer must not override 4002');

  // P2-C1 regression: Opening /view while host_lock_disconnect_blocked=true must latch manualReconnectRequired
  // with ZERO WebSocket connect or reconnect timer loop!
  const envLocked = createDomEnv(viewerHtml, {
    fetchImpl: async (url) => {
      if (url === '/api/auth/status') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            ...authReply,
            viewer_logged_in: true,
            viewer_approved: true,
            host_lock_disconnect_blocked: true,
          }),
        };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await envLocked.ctx.checkAuth();
  assert.equal(envLocked.wsInstances.length, 0, 'P2-C1: locked host must not open looping WS');
  assert.ok(
    envLocked.elements.get('streamStatus').textContent.includes('主机已锁屏'),
    'P2-C1: locked host must show lock-disconnect message'
  );

  // P1-B2 regression: P2P child receiving relayed init with SAME width/height/codec but BUMPED epoch
  // MUST reset MediaSource (preventing tfdt=0 self-deletion freeze)!
  const envP2pEpoch = createDomEnv(viewerHtml, {
    fetchImpl: async (url) => {
      if (url === '/api/auth/status') {
        return { ok: true, status: 200, json: async () => ({ ...authReply, viewer_logged_in: true, viewer_approved: true }) };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await envP2pEpoch.ctx.checkAuth();
  const wsEp = envP2pEpoch.wsInstances[envP2pEpoch.wsInstances.length - 1];
  wsEp.onmessage({
    data: JSON.stringify({ type: 'init', codec: 'avc1.42c01e', width: 1280, height: 720, source: 'ipad', epoch: 1, reset: true }),
  });
  const sbBeforeEpoch = envP2pEpoch.sourceBuffers.length;
  vm.runInContext('p2pActive = true;', envP2pEpoch.ctx);
  // Relayed P2P init (fromP2p = true) with identical 1280x720 + avc1.42c01e, but epoch: 2!
  const init2Json = JSON.stringify({ type: 'init', codec: 'avc1.42c01e', width: 1280, height: 720, source: 'main', epoch: 2, reset: true });
  envP2pEpoch.ctx.handleStreamMeta(JSON.parse(init2Json), init2Json, true);
  assert.equal(
    envP2pEpoch.sourceBuffers.length,
    sbBeforeEpoch + 1,
    'P1-B2: P2P child must reset MediaSource on same-dims/same-codec epoch change'
  );

  // Iter-6 P1-B2 regression: host_lock { locked: true } must clear lastMediaPayload so seedP2pChild
  // NEVER relays a stale pre-lock IDR via msgType=6!
  vm.runInContext('lastMediaPayload = new Uint8Array([0x02, 1, 2, 3]);', envP2pEpoch.ctx);
  wsEp.onmessage({ data: JSON.stringify({ type: 'host_lock', locked: true }) });
  assert.equal(
    vm.runInContext('lastMediaPayload === null', envP2pEpoch.ctx),
    true,
    'Iter-6 P1-B2: host_lock(true) must clear lastMediaPayload to prevent P2P pre-lock frame leak'
  );

  // Iter-6 P2-C1 regression: Aborting requestViewerApproval via viewerLogout() followed immediately
  // by a second approval request MUST NOT have its in-flight flag / button clobbered by the first finally!
  let resolveAppr1 = null;
  let apprCalls = 0;
  let apprAborted = false;
  const envApprAbort = createDomEnv(viewerHtml, {
    fetchImpl: async (url, opts) => {
      if (url === '/api/auth/status') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            ...authReply,
            viewer_logged_in: true,
            web_require_approval: true,
            viewer_approved: false,
          }),
        };
      }
      if (url === '/api/view/request-approval') {
        apprCalls += 1;
        if (apprCalls === 1) {
          if (opts?.signal) opts.signal.addEventListener('abort', () => { apprAborted = true; });
          return new Promise((res) => { resolveAppr1 = res; });
        }
        return new Promise(() => {});
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await envApprAbort.ctx.checkAuth();
  assert.equal(apprCalls, 1);
  // Logout aborts ctrl1 and resets viewerApprovalInFlight immediately
  const logoutP = envApprAbort.ctx.viewerLogout();
  assert.equal(apprAborted, true, 'Iter-6 P2-C1: viewerLogout must abort pending AbortController');
  await logoutP;
  // User immediately re-triggers approval (ctrl2 in flight) BEFORE ctrl1 promise settles
  const p2 = envApprAbort.ctx.requestViewerApproval(true);
  assert.equal(vm.runInContext('viewerApprovalInFlight', envApprAbort.ctx), true);
  // Now resolve stale ctrl1: its finally MUST NOT clobber ctrl2's viewerApprovalInFlight / btn.disabled!
  resolveAppr1({ ok: false, status: 401, json: async () => ({ error: 'aborted' }) });
  await new Promise((r) => setImmediate(r));
  assert.equal(
    vm.runInContext('viewerApprovalInFlight', envApprAbort.ctx),
    true,
    'Iter-6 P2-C1: stale aborted approval finally must NOT clobber newer approval in-flight state'
  );
  assert.equal(
    envApprAbort.elements.get('btnRetryApproval').disabled,
    true,
    'Iter-6 P2-C1: stale aborted approval finally must NOT re-enable retry button during active approval'
  );
  void p2;

  // Iter-7 P2-C4 regression: When /api/view/request-approval returns 401 Unauthorized (e.g. token rotated
  // or session revoked while waiting), viewer.html MUST call checkAuth() and return to secViewLogin!
  let auth401LoggedIn = true;
  const envAppr401 = createDomEnv(viewerHtml, {
    fetchImpl: async (url) => {
      if (url === '/api/auth/status') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            ...authReply,
            viewer_logged_in: auth401LoggedIn,
            web_require_approval: true,
            viewer_approved: false,
          }),
        };
      }
      if (url === '/api/view/request-approval') {
        auth401LoggedIn = false;
        return { ok: false, status: 401, json: async () => ({ ok: false, error: '会话已失效，请重新登录' }) };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await envAppr401.ctx.checkAuth();
  await new Promise((r) => setImmediate(r));
  assert.equal(
    envAppr401.elements.get('secViewLogin').classList.contains('hidden'),
    false,
    'Iter-7 P2-C4: 401 from /api/view/request-approval must transition back to secViewLogin'
  );
  assert.equal(
    envAppr401.elements.get('secViewApproval').classList.contains('hidden'),
    true,
    'Iter-7 P2-C4: secViewApproval must be hidden after 401 transition to secViewLogin'
  );

  // P1-C1 regression: Stale async 4001 onclose resolving AFTER user already called reconnectStream()
  // must NOT clobber the newer WS session or latch manualReconnectRequired!
  let resolveSlowAuth = null;
  const envRace = createDomEnv(viewerHtml, {
    fetchImpl: async (url) => {
      if (url === '/api/auth/status') {
        if (resolveSlowAuth === 'armed') {
          return new Promise((res) => {
            resolveSlowAuth = () => res({ ok: true, status: 200, json: async () => authReply });
          });
        }
        return { ok: true, status: 200, json: async () => authReply };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await envRace.ctx.checkAuth();
  const staleWs = envRace.wsInstances[envRace.wsInstances.length - 1];
  resolveSlowAuth = 'armed';
  const closePromise = staleWs.onclose({ code: 4001 });
  // While staleWs.onclose is suspended on `await api('/api/auth/status')`, user reconnects!
  const finishSlow = resolveSlowAuth;
  resolveSlowAuth = null;
  envRace.ctx.reconnectStream();
  await new Promise((r) => setImmediate(r));
  const newWsCount = envRace.wsInstances.length;
  // Now let the stale onclose fetch resolve: it MUST see streamGen !== myGen and exit cleanly!
  finishSlow();
  await closePromise;
  assert.equal(envRace.wsInstances.length, newWsCount, 'stale 4001 must not affect newer WS');
  assert.ok(
    !envRace.elements.get('streamStatus').textContent.includes('已被管理员断开'),
    'P1-C1 regression: stale 4001 async onclose must NOT overwrite status of fresh stream'
  );

  // GAP-C: visibilitychange 3s pause/resume + skip pause when relaying to P2P children
  const envVis = createDomEnv(viewerHtml, {
    fetchImpl: async (url) => {
      if (url === '/api/auth/status') {
        return { ok: true, status: 200, json: async () => ({ ...authReply, viewer_logged_in: true, viewer_approved: true }) };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await envVis.ctx.checkAuth();
  const wsVis = envVis.wsInstances[envVis.wsInstances.length - 1];
  wsVis.onopen();
  wsVis.sent.length = 0;
  envVis.ctx.document.hidden = true;
  for (const fn of envVis.docListeners.get('visibilitychange') || []) fn();
  const hideTimer = envVis.timers.find((t) => !t.cleared && t.ms === 3000);
  assert.ok(hideTimer, 'hiding tab must arm 3000ms pause timer');
  hideTimer.fn();
  assert.ok(
    wsVis.sent.some((m) => typeof m === 'string' && m.includes('"viewer_visibility"') && m.includes('false')),
    '3s hidden timer must send viewer_visibility=false'
  );
  // Returning to foreground sends viewer_visibility=true + need_idr
  wsVis.sent.length = 0;
  envVis.ctx.document.hidden = false;
  for (const fn of envVis.docListeners.get('visibilitychange') || []) fn();
  assert.ok(
    wsVis.sent.some((m) => typeof m === 'string' && m.includes('"viewer_visibility"') && m.includes('true')),
    'showing tab must send viewer_visibility=true'
  );
  assert.ok(
    wsVis.sent.some((m) => typeof m === 'string' && m.includes('"need_idr"')),
    'showing tab after hidden pause must request fresh IDR'
  );
  // If viewer is actively relaying to a P2P child, hiding tab must NOT pause server push!
  vm.runInContext('p2pChildren.set(99, { pc: null, dc: null });', envVis.ctx);
  wsVis.sent.length = 0;
  envVis.ctx.document.hidden = true;
  for (const fn of envVis.docListeners.get('visibilitychange') || []) fn();
  const hideTimerRelay = [...envVis.timers].reverse().find((t) => !t.cleared && t.ms === 3000);
  if (hideTimerRelay) hideTimerRelay.fn();
  assert.equal(
    wsVis.sent.some((m) => typeof m === 'string' && m.includes('"viewer_visibility"') && m.includes('false')),
    false,
    'P2P relay parent must NOT send viewer_visibility=false while serving P2P children'
  );

  // GAP-C: P2P 3-chunk binary reassembly (onP2pDataMessage) + p2p_parent_lost fallback
  wsVis.onmessage({
    data: JSON.stringify({ type: 'init', codec: 'avc1.42c01e', width: 1280, height: 720, source: 'main', reset: true }),
  });
  wsVis.onmessage({ data: new Uint8Array([0x01, 0, 0, 0, 1, 0x66, 0x74, 0x79, 0x70]).buffer });
  const sbP2p = envVis.sourceBuffers[envVis.sourceBuffers.length - 1];
  const beforeP2p = sbP2p.appended.length;
  // Build 3 chunks for msgType=2 (IDR), seq=7 with 9-byte header: [msgType(1B), seq(u32BE), chunkIdx(u16BE), chunkCount(u16BE)]
  const makeP2pChunk = (seq, idx, total, body) => {
    const buf = new Uint8Array(9 + body.length);
    buf[0] = 2;
    buf[1] = (seq >>> 24) & 0xff;
    buf[2] = (seq >>> 16) & 0xff;
    buf[3] = (seq >>> 8) & 0xff;
    buf[4] = seq & 0xff;
    buf[5] = (idx >> 8) & 0xff;
    buf[6] = idx & 0xff;
    buf[7] = (total >> 8) & 0xff;
    buf[8] = total & 0xff;
    buf.set(body, 9);
    return buf.buffer;
  };
  // Arm P2P parent assignment (`p2pParentId = 42`) so 3-chunk IDR promotes `p2pActive = true`
  vm.runInContext('p2pParentId = 42;', envVis.ctx);
  envVis.ctx.onP2pDataMessage(makeP2pChunk(7, 0, 3, [1, 2, 3]), 42);
  envVis.ctx.onP2pDataMessage(makeP2pChunk(7, 1, 3, [4, 5, 6]), 42);
  assert.equal(sbP2p.appended.length, beforeP2p, 'incomplete 2/3 P2P frame must not append yet');
  envVis.ctx.onP2pDataMessage(makeP2pChunk(7, 2, 3, [7, 8, 9]), 42);
  assert.equal(sbP2p.appended.length, beforeP2p + 1, 'completed 3/3 P2P IDR frame must reassemble and append');
  assert.deepEqual([...sbP2p.appended[sbP2p.appended.length - 1]], [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.ok(
    wsVis.sent.some((m) => typeof m === 'string' && m.includes('"p2p_active"') && m.includes('42')),
    'completed P2P IDR from assigned parent must announce p2p_active over WS'
  );
  // p2p_parent_lost must re-arm mseAwaitingIdr so a stale WS P-frame is dropped!
  wsVis.onmessage({ data: JSON.stringify({ type: 'p2p_parent_lost' }) });
  const afterLostCount = sbP2p.appended.length;
  wsVis.onmessage({ data: new Uint8Array([0x03, 9, 9, 9]).buffer });
  assert.equal(sbP2p.appended.length, afterLostCount, 'p2p_parent_lost must re-arm mseAwaitingIdr and drop P-frame');

  // QuotaExceededError recovery (fresh isolated env): kind===1 init segment preserved & need_idr sent
  const envQ = createDomEnv(viewerHtml, {
    fetchImpl: async (url) => {
      if (url === '/api/auth/status') {
        return { ok: true, status: 200, json: async () => ({ ...authReply, viewer_logged_in: true, viewer_approved: true }) };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await envQ.ctx.checkAuth();
  const wsQuota = envQ.wsInstances[envQ.wsInstances.length - 1];
  wsQuota.onmessage({
    data: JSON.stringify({ type: 'init', codec: 'avc1.42c01e', width: 1280, height: 720, source: 'main', reset: true }),
  });
  const sbQuota = envQ.sourceBuffers[envQ.sourceBuffers.length - 1];
  let removeCalled = false;
  envQ.elements.get('screenVideo').buffered = { length: 1, start: () => 0, end: () => 5.0 };
  sbQuota.remove = () => { removeCalled = true; };
  let threwOnce = false;
  const origAppend = sbQuota.appendBuffer.bind(sbQuota);
  sbQuota.appendBuffer = (buf) => {
    if (!threwOnce) {
      threwOnce = true;
      const e = new Error('quota');
      e.name = 'QuotaExceededError';
      throw e;
    }
    return origAppend(buf);
  };
  wsQuota.onmessage({ data: new Uint8Array([0x01, 0, 0, 0, 1, 0x66, 0x74, 0x79, 0x70]).buffer });
  assert.equal(removeCalled, true, 'QuotaExceededError must trim SourceBuffer');
  assert.ok(
    wsQuota.sent.some((m) => typeof m === 'string' && m.includes('need_idr')),
    'QuotaExceededError must request fresh IDR'
  );
}
console.log('PASS [2/5]: viewer.html approval, 4001 non-reconnect, QuotaExceededError, MSE IDR gate & keydown guard');

// =========================================================================
// 3. admin.html Behavioral Tests (BUG-C7 pendingByAddr, XSS esc, low_power toast)
// =========================================================================
{
  let fakeAdminState = null;
  const lowPowerTokenBodies = [];
  const env = createDomEnv(adminHtml, {
    fetchImpl: async (url, opts) => {
      if (url === '/api/admin/state') {
        return { ok: true, status: 200, json: async () => fakeAdminState };
      }
      if (url === '/api/admin/settings' && opts?.method === 'POST') {
        lowPowerTokenBodies.push(JSON.parse(opts.body));
        return {
          ok: true,
          status: 200,
          json: async () => ({
            ok: true,
            view_token: 'tok12345',
            generated_view_token: 'gen99999',
            low_power: true,
            p2p_relay_enabled: false,
            max_web_viewers: 0, // low_power clamped to 0!
          }),
        };
      }
      return { ok: true, status: 200, json: async () => ({ admin_logged_in: true }) };
    },
  });

  // XSS escaping test
  assert.equal(
    env.ctx.esc('<img src=x onerror="alert(1)">&\''),
    '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&amp;&#39;'
  );

  // BUG-C7 regression: pendingByAddr must NOT let a Web pending approval overwrite an iPad approval on the same IP!
  fakeAdminState = {
    host: {
      host_name: 'TestMac',
      os: 'macos',
      arch: 'aarch64',
      version: '0.3.1',
      mode: 'Extend',
      wifi: true,
      usb: true,
      uptime_secs: 42,
      supports_hidpi: true,
      supports_independent_web_screen: true,
      capabilities: {
        hidpi: true,
        virtual_display: true,
        screen_lock_detection: true,
        live_abr_quality: true,
        true_capture_pause: true,
        accessibility_permission_required: false,
        accessibility_granted: true,
      },
      process: { pid: 1234, cpu_pct: 1.5, rss_bytes: 20 * 1024 * 1024, host_cpu_pct: 10, host_mem_used_bytes: 1e9, host_mem_total_bytes: 16e9 },
    },
    connection: {
      lan_ips: ['192.168.1.10'],
      primary_ip: '192.168.1.10',
      wifi_enabled: true,
      wifi_telemetry_port: 5026,
      wifi_data_port: 5027,
      wifi_endpoints: ['192.168.1.10:5026'],
      web_bind: '127.0.0.1:8787',
      web_localhost_only: true,
      web_admin_urls: ['http://127.0.0.1:8787/'],
      web_viewer_bind: null,
      web_viewer_port: null,
      web_viewer_listening: false,
      web_viewer_urls: [],
      web_viewer_token_urls: [],
    },
    video: {
      width: 0, height: 0, fps: 30, bitrate_mbps: 16, hidpi: 1, integer_scale: false,
      max_pixel_edge: 0, adaptive_quality: true, half_fps_when_unfocused: true, quality: 'balanced',
      web_width: 1280, web_height: 720, web_fps: 30, web_bitrate_mbps: 16, web_hidpi: 1,
      web_max_pixel_edge: 0, web_quality: 'balanced',
    },
    settings: {
      allow_input: false,
      client_cursor: true,
      input_stats: { injected_total: 0, dropped_disabled: 0, dropped_locked: 0 },
      max_extended_screens: 2,
      active_extended_screens: 0,
      max_web_viewers: 0,
      active_web_viewers: 0,
      auto_max_in_flight: true,
      max_in_flight: 2,
      view_token_enabled: false,
      web_independent_screen: false,
      web_screen_mode: 'main',
      web_require_approval: true,
      lock_action_ipad: 'pause',
      lock_action_web: 'disconnect',
      lock_delay_secs: 10,
      host_screen_locked: false,
      host_lock_enforced: false,
      p2p_relay_enabled: true,
      low_power: true,
      polling: { main_loop_ms: 250, cursor_poll_ms: 33, usb_retry_ms: 2000, admin_poll_ms: 4000 },
    },
    web_screen: { mode: 'main', independent: false, supported: true, active: false, source: 'idle', width: 1280, height: 720, logical_width: 1280, logical_height: 720, hidpi: 1 },
    web_p2p: { enabled: false, active_relays: 0, relayed_viewers: 0, max_depth: 0, peers: [] },
    cli_config: {
      mode: 'extend', wifi: true, no_usb: false, no_bonjour: false, bind_addr: '0.0.0.0',
      telemetry_port: 5026, data_port: 5027, host_name: 'TestMac', display_id: 0,
      client_cursor: true, half_fps_when_unfocused: true, web_screen_mode: 'main', web_require_approval: true,
      ping_timeout_secs: 20, idle_exit_secs: 300, trust_usb: false, require_usb_confirm: false,
      low_power: true, auto_accept: false, no_confirm: false, web_bind: '0.0.0.0:8787',
      web_width: 1280, web_height: 720, web_fps: 30, web_bitrate_mbps: 16, web_hidpi: 1,
      web_max_pixel_edge: 0, qr: false, debug: false, all_intra: false, allow_ips: [], allow_fingerprints: [],
    },
    sessions: [
      {
        id: 1, key: '192.168.1.50', name: 'My iPad', model: 'iPad Air', transport: 'Wi-Fi',
        fingerprint: 'fp:aaaaaaaaaaaaaaaaaaaaaaaa', authorized: false, awaiting_confirm: true, streaming: false,
        logical_width: 1024, logical_height: 768, width: 1024, height: 768, hidpi: 1, is_pixel_exact: true,
        in_flight: 0, max_in_flight: 2, dropped_frames: 0, auto_max_in_flight: true,
        abr: { enabled: true, tier: 0, scale_pct: 100, target_fps: 30, target_bitrate_mbps: 16, rtt_ms: null, unfocused_fps_halved: true },
      },
    ],
    web_viewers: [],
    pending_approvals: [
      { id: 101, addr: '192.168.1.50', fingerprint: 'fp:aaaaaaaaaaaaaaaaaaaaaaaa', name: 'My iPad', model: 'iPad Air', is_usb: false, is_web: false, waiting_secs: 3 },
      { id: 202, addr: '192.168.1.50', fingerprint: 'fp:bbbbbbbbbbbbbbbbbbbbbbbb', name: 'Chrome / macOS', model: 'Web Browser', is_usb: false, is_web: true, waiting_secs: 1 },
    ],
    trusted_devices: [],
    active_preset: null,
    presets: [],
    builtin_presets: [],
    logs: [],
  };

  await env.ctx.checkAuth();
  await env.ctx.refreshAdmin();
  // Iter-10 P2-C1 regression: On the VERY FIRST refreshAdmin() with low_power=true,
  // renderConnectionGuide() must already show the low-power pause notice (NOT enableWebViewingQuick)
  // AND show the split viewer port as closed (never suggesting --web-bind 0.0.0.0:8787)!
  const lpLinksHtml = env.elements.get('viewerLinksBox').innerHTML;
  assert.ok(
    lpLinksHtml.includes('当前处于低电量模式') && !lpLinksHtml.includes('enableWebViewingQuick()'),
    `Iter-10 P2-C1: initial refreshAdmin(low_power=true) must show low-power pause notice; got: ${lpLinksHtml}`
  );
  assert.ok(
    lpLinksHtml.includes('扩展屏端口已关闭') && !lpLinksHtml.includes('--web-bind 0.0.0.0:8787'),
    `Split-port UI must show closed viewer port without --web-bind warning; got: ${lpLinksHtml}`
  );
  // Flipping low_power -> false must immediately show enableWebViewingQuick() on the very next refreshAdmin()!
  fakeAdminState.settings.low_power = false;
  await env.ctx.refreshAdmin();
  const normalLinksHtml = env.elements.get('viewerLinksBox').innerHTML;
  assert.ok(
    normalLinksHtml.includes('enableWebViewingQuick()') && !normalLinksHtml.includes('当前处于低电量模式'),
    `Iter-10 P2-C1: refreshAdmin(low_power=false) must immediately restore quick-enable button; got: ${normalLinksHtml}`
  );
  // When Viewer port opens on a random 0.0.0.0:<port>, renderConnectionGuide must show the port badge, close button, countdown & isolated notice!
  fakeAdminState.settings.max_web_viewers = 2;
  fakeAdminState.settings.port_idle_close_secs = 300;
  fakeAdminState.connection.web_viewer_listening = true;
  fakeAdminState.connection.web_viewer_port = 54321;
  fakeAdminState.connection.web_viewer_bind = '0.0.0.0:54321';
  fakeAdminState.connection.web_viewer_urls = ['http://192.168.1.10:54321/view'];
  fakeAdminState.connection.web_viewer_token_urls = ['http://192.168.1.10:54321/view?token=abc12345'];
  fakeAdminState.connection.web_viewer_idle_remaining_secs = 90;
  fakeAdminState.connection.wifi_enabled = true;
  fakeAdminState.connection.wifi_idle_remaining_secs = 125;
  await env.ctx.refreshAdmin();
  const openLinksHtml = env.elements.get('viewerLinksBox').innerHTML;
  assert.ok(
    openLinksHtml.includes('扩展屏端口已开启')
      && openLinksHtml.includes('0.0.0.0:54321')
      && openLinksHtml.includes('192.168.1.10:54321/view?token=abc12345')
      && openLinksHtml.includes('closeWebViewerPort()')
      && openLinksHtml.includes('空闲 1分30秒 后关闭'),
    `Split-port UI must show open random 0.0.0.0:<port> viewer address, close button & idle countdown; got: ${openLinksHtml}`
  );
  const wifiOpenHtml = env.elements.get('wifiConnCard').innerHTML;
  assert.ok(
    wifiOpenHtml.includes('toggleWifiPort(false)') && wifiOpenHtml.includes('空闲 2分5秒 后关闭'),
    `Wi-Fi card must render close switch & idle countdown when enabled; got: ${wifiOpenHtml}`
  );
  fakeAdminState.connection.wifi_enabled = false;
  fakeAdminState.connection.wifi_idle_remaining_secs = null;
  await env.ctx.refreshAdmin();
  const wifiClosedHtml = env.elements.get('wifiConnCard').innerHTML;
  assert.ok(
    wifiClosedHtml.includes('toggleWifiPort(true)') && wifiClosedHtml.includes('开启 Wi-Fi 端口'),
    `Wi-Fi card must render dynamic enable switch when closed; got: ${wifiClosedHtml}`
  );
  // Dynamic Telemetry-TCP cursor warning regression: must react to streaming/udp_cursor transitions
  // even when ipadSig is unchanged or videoFormDirty === true.
  const savedSessionsForCursorTest = fakeAdminState.sessions;
  const savedClientCursorForTest = fakeAdminState.settings.client_cursor;
  fakeAdminState.settings.client_cursor = true;
  fakeAdminState.sessions = [{
    id: 1, key: '10.11.59.205', name: 'iPad', model: 'iPad', transport: 'wifi',
    authorized: true, awaiting_confirm: false, streaming: false,
    logical_width: 1024, logical_height: 768, width: 2048, height: 1536,
    native_width: 2048, native_height: 1536, hidpi: 2, is_pixel_exact: true,
    in_flight: 0, max_in_flight: 4, dropped_frames: 0, auto_max_in_flight: true,
    udp_cursor: false,
  }];
  await env.ctx.refreshAdmin();
  assert.ok(
    env.elements.get('ipadCursorWarn').classList.contains('hidden'),
    'ipadCursorWarn must stay hidden before streaming starts'
  );
  // Flip streaming -> true (ipadSig unchanged): warning must appear immediately!
  fakeAdminState.sessions[0].streaming = true;
  await env.ctx.refreshAdmin();
  assert.ok(
    !env.elements.get('ipadCursorWarn').classList.contains('hidden')
      && env.elements.get('ipadCursorWarn').textContent.includes('Telemetry TCP'),
    'ipadCursorWarn must show when Wi-Fi streaming session lacks UDP cursor'
  );
  // Even while videoFormDirty === true, switching udp_cursor -> true must hide warning immediately!
  env.ctx.setVideoDirty(true);
  fakeAdminState.sessions[0].udp_cursor = true;
  await env.ctx.refreshAdmin();
  assert.ok(
    env.elements.get('ipadCursorWarn').classList.contains('hidden'),
    'ipadCursorWarn must hide when session has UDP cursor even while form is dirty'
  );
  env.ctx.setVideoDirty(false);
  fakeAdminState.settings.client_cursor = savedClientCursorForTest;
  fakeAdminState.sessions = savedSessionsForCursorTest;
  // Restore low_power=true + closed viewer port for subsequent low-power tests below
  fakeAdminState.settings.low_power = true;
  fakeAdminState.settings.max_web_viewers = 0;
  fakeAdminState.connection.wifi_enabled = true;
  fakeAdminState.connection.web_viewer_listening = false;
  fakeAdminState.connection.web_viewer_port = null;
  fakeAdminState.connection.web_viewer_bind = null;
  fakeAdminState.connection.web_viewer_urls = [];
  fakeAdminState.connection.web_viewer_token_urls = [];
  fakeAdminState.connection.web_viewer_idle_remaining_secs = null;
  await env.ctx.refreshAdmin();
  const sessionsHtml = env.elements.get('sessionsBody').innerHTML;
  assert.ok(sessionsHtml.includes('data-id="101"'), `iPad row must wire to iPad pending ID 101; got: ${sessionsHtml}`);
  assert.ok(!sessionsHtml.includes('data-id="202"'), 'Web pending ID 202 must NEVER hijack same-IP iPad row');
  assert.ok(sessionsHtml.includes('失焦降帧'), 'session row must render unfocused half-FPS badge');

  // BUG-C7 + Iter-8 P2-C1 regression: setViewToken/rotateViewToken under low_power MUST NOT inject
  // max_web_viewers: 1 (which would clobber low_power_snapshot & disk baseline!) or falsely claim limit=1.
  lowPowerTokenBodies.length = 0;
  env.elements.get('newViewToken').value = 'tok12345';
  await env.ctx.setViewToken();
  assert.equal(
    'max_web_viewers' in lowPowerTokenBodies[0],
    false,
    `Iter-8 P2-C1: setViewToken under low_power must NOT inject max_web_viewers; got ${JSON.stringify(lowPowerTokenBodies[0])}`
  );
  assert.ok(
    !env.elements.get('viewTokenMsg').innerHTML.includes('已自动将网页观看上限设为 1'),
    'setViewToken must not lie about max_web_viewers=1 when low_power clamped it to 0'
  );
  await env.ctx.rotateViewToken();
  assert.equal(
    'max_web_viewers' in lowPowerTokenBodies[1],
    false,
    `Iter-8 P2-C1: rotateViewToken under low_power must NOT inject max_web_viewers; got ${JSON.stringify(lowPowerTokenBodies[1])}`
  );
  assert.ok(
    !env.elements.get('viewTokenMsg').innerHTML.includes('已自动将网页观看上限设为 1'),
    'rotateViewToken must not lie about max_web_viewers=1 when low_power clamped it to 0'
  );

  // Iter-9 P2-C2 regression: enableWebViewingQuick() & toggleP2pRelay() under low_power MUST NOT
  // show false-positive "enabled" toasts when backend keeps runtime clamped!
  const lpToasts = [];
  env.elements.get('toastStack').appendChild = (el) => { lpToasts.push(el.textContent); return el; };
  await env.ctx.enableWebViewingQuick();
  assert.ok(
    lpToasts.some((t) => t.includes('低电量模式')),
    `Iter-9 P2-C2: enableWebViewingQuick under low_power must note deferred low-power state; toasts=${JSON.stringify(lpToasts)}`
  );
  assert.ok(
    !lpToasts.some((t) => t.includes('已允许网页观看（观看上限设为 1）')),
    'Iter-9 P2-C2: enableWebViewingQuick must NOT emit false-positive enabled toast under low_power'
  );
  lpToasts.length = 0;
  vm.runInContext('lastP2pRelayEnabled = false;', env.ctx);
  await env.ctx.toggleP2pRelay();
  assert.ok(
    lpToasts.some((t) => t.includes('低电量模式')),
    `Iter-9 P2-C2: toggleP2pRelay under low_power must note deferred low-power state; toasts=${JSON.stringify(lpToasts)}`
  );
  assert.ok(
    !lpToasts.some((t) => t.includes('已开启局域网 P2P 加速')),
    'Iter-9 P2-C2: toggleP2pRelay must NOT emit false-positive enabled toast under low_power'
  );

  // GAP-C: confirmDanger 2-step arm / confirm / auto-disarm
  const dangerBtn = makeMockElement('dangerTestBtn');
  dangerBtn.textContent = '断开全部';
  let dangerFired = 0;
  env.ctx.confirmDanger(dangerBtn, '确认断开？', () => { dangerFired++; });
  assert.equal(dangerFired, 0, '1st click must arm, not execute');
  assert.equal(dangerBtn.textContent, '确认断开？');
  env.ctx.confirmDanger(dangerBtn, '确认断开？', () => { dangerFired++; });
  assert.equal(dangerFired, 1, '2nd click while armed must execute callback');
  assert.equal(dangerBtn.textContent, '断开全部', '2nd click must restore original label');
  // Re-arm and let auto-disarm timer fire
  const timerCountBefore = env.timers.length;
  env.ctx.confirmDanger(dangerBtn, '确认断开？', () => { dangerFired++; });
  assert.equal(dangerBtn.textContent, '确认断开？');
  const disarmTimer = env.timers.slice(timerCountBefore).find((t) => !t.cleared && !t.interval);
  assert.ok(disarmTimer, 'confirmDanger must schedule auto-disarm timer');
  disarmTimer.fn();
  assert.equal(dangerBtn.textContent, '断开全部', 'auto-disarm timer must restore original label');
  assert.equal(dangerFired, 1, 'auto-disarm must NOT execute callback');

  // P2-C7 regression: applyConfigPreset must clear dirty SKU badges via setVideoDirty(false)/setWebDirty(false)
  env.ctx.setVideoDirty(true);
  env.ctx.setWebDirty(true);
  assert.equal(env.elements.get('videoDirtyBadge').classList.contains('hidden'), false);
  await env.ctx.applyConfigPreset('极简省电');
  assert.equal(
    env.elements.get('videoDirtyBadge').classList.contains('hidden'),
    true,
    'P2-C7: applyConfigPreset must clear videoDirtyBadge UI state'
  );
  assert.equal(
    env.elements.get('webDirtyBadge').classList.contains('hidden'),
    true,
    'P2-C7: applyConfigPreset must clear webDirtyBadge UI state'
  );

  // P1-C3 + Iter-6 P2-C2 regression: applyIpadSkuSettings & applyWebSkuSettings must send ONLY changed
  // fields (diff-patch), immediately update server baseline for back-to-back toggles before refreshAdmin()
  // settles, AND saveConfigYaml/loadConfigYaml(true)/resetConfigYaml must clear dirty flags!
  const capturedSettingsBodies = [];
  let liveVideo = { ...fakeAdminState.video };
  let liveSettings = { ...fakeAdminState.settings };
  const envDiff = createDomEnv(adminHtml, {
    fetchImpl: async (url, opts) => {
      if (url === '/api/admin/state') {
        return { ok: true, status: 200, json: async () => ({ ...fakeAdminState, video: liveVideo, settings: liveSettings }) };
      }
      if (url === '/api/admin/settings' && opts?.method === 'POST') {
        const body = JSON.parse(opts.body);
        capturedSettingsBodies.push(body);
        if (typeof body.client_cursor === 'boolean') liveSettings = { ...liveSettings, client_cursor: body.client_cursor };
        if (typeof body.web_require_approval === 'boolean') liveSettings = { ...liveSettings, web_require_approval: body.web_require_approval };
        return { ok: true, status: 200, json: async () => ({ ok: true, ...liveSettings, video: liveVideo }) };
      }
      if (url === '/api/admin/config' || url === '/api/admin/config/reload' || url === '/api/admin/config/reset') {
        return { ok: true, status: 200, json: async () => ({ ok: true, yaml: 'allow_input: false\n', path: '/tmp/idis.yaml' }) };
      }
      if (url === '/api/admin/pending/decide') {
        return { ok: true, status: 200, json: async () => ({ ok: false }) };
      }
      return { ok: true, status: 200, json: async () => ({ admin_logged_in: true }) };
    },
  });
  await envDiff.ctx.checkAuth();
  await envDiff.ctx.refreshAdmin();
  // Flip ONLY clientCursor on ipadDraft -> payload must contain ONLY { client_cursor: false } (NOT fps/bitrate/hidpi!)
  vm.runInContext('ipadDraft.clientCursor = !ipadDraft.clientCursor;', envDiff.ctx);
  await envDiff.ctx.applyIpadSkuSettings();
  assert.deepEqual(
    capturedSettingsBodies[0],
    { client_cursor: false },
    `P1-C3: applyIpadSkuSettings must send diff-patch only; got ${JSON.stringify(capturedSettingsBodies[0])}`
  );
  // Iter-6 P2-C2: Immediately flip clientCursor back to true BEFORE waiting for refreshAdmin() -> MUST send { client_cursor: true }!
  vm.runInContext('ipadDraft.clientCursor = true; setVideoDirty(true);', envDiff.ctx);
  await envDiff.ctx.applyIpadSkuSettings();
  assert.deepEqual(
    capturedSettingsBodies[1],
    { client_cursor: true },
    `Iter-6 P2-C2: back-to-back applyIpadSkuSettings must use updated baseline; got ${JSON.stringify(capturedSettingsBodies[1])}`
  );
  // Flip ONLY requireApproval on webDraft -> payload must contain ONLY { web_require_approval: false }!
  vm.runInContext('webDraft.requireApproval = !webDraft.requireApproval;', envDiff.ctx);
  await envDiff.ctx.applyWebSkuSettings();
  assert.deepEqual(
    capturedSettingsBodies[2],
    { web_require_approval: false },
    `P1-C3: applyWebSkuSettings must send diff-patch only; got ${JSON.stringify(capturedSettingsBodies[2])}`
  );
  // Iter-6 P2-C2: saveConfigYaml(), loadConfigYaml(true), and resetConfigYaml() must clear video/web dirty flags!
  envDiff.ctx.setVideoDirty(true);
  envDiff.ctx.setWebDirty(true);
  await envDiff.ctx.saveConfigYaml();
  assert.equal(envDiff.elements.get('videoDirtyBadge').classList.contains('hidden'), true, 'Iter-6 P2-C2: saveConfigYaml clears videoFormDirty');
  assert.equal(envDiff.elements.get('webDirtyBadge').classList.contains('hidden'), true, 'Iter-6 P2-C2: saveConfigYaml clears webFormDirty');
  envDiff.ctx.setVideoDirty(true);
  envDiff.ctx.setWebDirty(true);
  await envDiff.ctx.loadConfigYaml(true, true);
  assert.equal(envDiff.elements.get('videoDirtyBadge').classList.contains('hidden'), true, 'Iter-6 P2-C2: loadConfigYaml(reload) clears videoFormDirty');
  assert.equal(envDiff.elements.get('webDirtyBadge').classList.contains('hidden'), true, 'Iter-6 P2-C2: loadConfigYaml(reload) clears webFormDirty');
  envDiff.ctx.setVideoDirty(true);
  envDiff.ctx.setWebDirty(true);
  await envDiff.ctx.resetConfigYaml();
  assert.equal(envDiff.elements.get('videoDirtyBadge').classList.contains('hidden'), true, 'Iter-6 P2-C2: resetConfigYaml clears videoFormDirty');
  assert.equal(envDiff.elements.get('webDirtyBadge').classList.contains('hidden'), true, 'Iter-6 P2-C2: resetConfigYaml clears webFormDirty');

  // P2-C3 regression: decidePending() when backend returns HTTP 200 { ok: false } must NOT show green success toast!
  const toastTexts = [];
  envDiff.elements.get('toastStack').appendChild = (el) => { toastTexts.push(el.textContent); return el; };
  await envDiff.ctx.decidePending(999, 'allow_once');
  assert.ok(
    toastTexts.some((t) => t.includes('已过期') || t.includes('已断开')),
    `P2-C3: decidePending({ok:false}) must warn about expired/disconnected slot; toasts=${JSON.stringify(toastTexts)}`
  );
  assert.ok(
    !toastTexts.some((t) => t.includes('已放行连接请求')),
    'P2-C3: decidePending({ok:false}) must NOT display false-positive success toast'
  );

  // Guard: SKU option chip labels must stay concise with zero parenthetical filler like (默认)/(低延迟)
  const chipLabelMatches = [...adminHtml.matchAll(/label:\s*'([^']+)'/g)].map((m) => m[1]);
  const noisyLabels = chipLabelMatches.filter((l) => /[（(]/.test(l));
  assert.deepEqual(
    noisyLabels,
    [],
    `admin.html option labels must not contain parenthetical descriptions: ${JSON.stringify(noisyLabels)}`
  );

  // Guard: Guided macOS Screen Recording permission banner & capture error banner isolation + one-click API
  const permRequests = [];
  let permStatePayload = {
    host: {
      host_name: 'MacTest',
      os: 'macos',
      arch: 'aarch64',
      version: '0.3.9',
      mode: 'Extend',
      fps: 30,
      bitrate_mbps: 16,
      wifi: true,
      usb: true,
      uptime_secs: 10,
      executable_path: '/opt/homebrew/bin/idis',
      capabilities: {
        hidpi: true,
        virtual_display: true,
        window_routing: true,
        screen_lock_detection: true,
        live_abr_quality: true,
        true_capture_pause: true,
        accessibility_permission_required: true,
        accessibility_granted: false,
        screen_recording_permission_required: true,
        screen_recording_granted: false,
      },
      last_capture_error: {
        code: 'screen_recording_denied',
        source: 'ipad',
        message: 'macOS 拒绝了屏幕录制权限',
        ts_unix: 1,
      },
    },
    connection: { lan_ips: ['127.0.0.1'], web_admin_urls: ['http://127.0.0.1:8787/'], web_viewer_urls: [], wifi_endpoints: [] },
    settings: {
      allow_input: true,
      client_cursor: false,
      input_stats: {},
      wifi_enabled: true,
      max_extended_screens: 2,
      active_extended_screens: 0,
      max_web_viewers: 1,
      active_web_viewers: 0,
      auto_max_in_flight: true,
      max_in_flight: 2,
      view_token_enabled: false,
      web_screen_mode: 'follow_ipad',
      web_require_approval: false,
      lock_action_ipad: 'pause',
      lock_action_web: 'pause',
      lock_delay_secs: 10,
      low_power: false,
      polling: { main_loop_ms: 250, cursor_poll_ms: 8, usb_retry_ms: 1000, admin_poll_ms: 2000 },
    },
    video: { width: 0, height: 0, fps: 30, bitrate_mbps: 16, hidpi: 1, max_pixel_edge: 0, adaptive_quality: true, abr_sensitivity: 'balanced', web_width: 1280, web_height: 720, web_fps: 30, web_bitrate_mbps: 16, web_hidpi: 1, web_max_pixel_edge: 0 },
    cli_config: {},
    sessions: [],
    pending_approvals: [],
    trusted_devices: [],
    web_viewers: [],
    screens: [],
    virtual_displays: [],
    window_rules: [],
    presets: [],
    builtin_presets: [],
    logs: [],
  };
  const envPerm = createDomEnv(adminHtml, {
    fetchImpl: async (url, opts) => {
      if (url === '/api/auth/status') {
        return { ok: true, status: 200, json: async () => ({ admin_logged_in: true, viewer_logged_in: false, viewer_enabled: false }) };
      }
      if (url === '/api/admin/state') {
        return { ok: true, status: 200, json: async () => permStatePayload };
      }
      if (url === '/api/admin/permissions/request') {
        permRequests.push(JSON.parse(opts.body));
        return { ok: true, status: 200, json: async () => ({ ok: true, message: '已在主机上打开系统设置' }) };
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
  });
  await envPerm.ctx.checkAuth();
  await envPerm.ctx.refreshAdmin();
  assert.equal(envPerm.elements.get('screenRecordingWarnBanner').classList.contains('hidden'), false, 'missing Screen Recording permission must show guided banner');
  assert.equal(envPerm.elements.get('screenRecExePath').textContent, '/opt/homebrew/bin/idis', 'banner must display host executable_path');
  assert.equal(envPerm.elements.get('captureErrorBanner').classList.contains('hidden'), true, 'screen_recording_denied must not show duplicate generic captureErrorBanner');
  assert.equal(envPerm.elements.get('accessibilityWarnBanner').classList.contains('hidden'), false, 'missing Accessibility with allow_input=true must show guided banner');

  await envPerm.ctx.requestOsPermission('screen_recording');
  assert.deepEqual(permRequests[0], { kind: 'screen_recording' }, 'requestOsPermission must POST { kind } to /api/admin/permissions/request');

  // Switch to granted + generic capture_failed -> generic banner shows exact message, permission banner hides
  permStatePayload.host.capabilities.screen_recording_granted = true;
  permStatePayload.host.last_capture_error = { code: 'capture_failed', source: 'web', message: '虚拟屏尚未就绪', ts_unix: 2 };
  await envPerm.ctx.refreshAdmin();
  assert.equal(envPerm.elements.get('screenRecordingWarnBanner').classList.contains('hidden'), true, 'granted permission must hide screenRecordingWarnBanner');
  assert.equal(envPerm.elements.get('captureErrorBanner').classList.contains('hidden'), false, 'capture_failed must show captureErrorBanner');
  assert.equal(envPerm.elements.get('captureErrorDetail').textContent, '虚拟屏尚未就绪');
}
console.log('PASS [3/5]: admin.html pendingByAddr isolation, XSS escaping, unfocused badge & low_power toast');

// =========================================================================
// 4. Verify CLI command builder flags match Rust AppConfig CLI grammar
// =========================================================================
{
  const env = createDomEnv(adminHtml, {
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({}) }),
  });
  const cli = env.ctx.buildCliCommand({
    cli_config: {
      mode: 'extend', wifi: true, no_usb: false, no_bonjour: false, bind_addr: '0.0.0.0',
      telemetry_port: 5026, data_port: 5027, host_name: 'Mac', display_id: 0,
      client_cursor: true, half_fps_when_unfocused: true, web_screen_mode: 'main', web_require_approval: true,
      ping_timeout_secs: 20, idle_exit_secs: 300, trust_usb: false, require_usb_confirm: false,
      low_power: false, auto_accept: false, no_confirm: false, web_bind: '0.0.0.0:8787',
      web_width: 1280, web_height: 720, web_fps: 30, web_bitrate_mbps: 16, web_hidpi: 1,
      web_max_pixel_edge: 0, qr: false, debug: false, all_intra: false, allow_ips: [], allow_fingerprints: [],
    },
    video: {
      width: 0, height: 0, fps: 30, bitrate_mbps: 16, hidpi: 1, integer_scale: false,
      max_pixel_edge: 0, adaptive_quality: true, abr_sensitivity: 'conservative', half_fps_when_unfocused: true,
      web_width: 1280, web_height: 720, web_fps: 30, web_bitrate_mbps: 16, web_hidpi: 1, web_max_pixel_edge: 0,
    },
    settings: {
      allow_input: true, client_cursor: true, max_extended_screens: 2, max_web_viewers: 4,
      auto_max_in_flight: true, max_in_flight: 2, web_screen_mode: 'main', web_require_approval: true,
      lock_action_ipad: 'pause', lock_action_web: 'disconnect', lock_delay_secs: 10, low_power: false,
    },
  });
  assert.ok(cli.includes('--client-cursor'), `expected --client-cursor in: ${cli}`);
  assert.ok(cli.includes('--half-fps-unfocused'), `expected --half-fps-unfocused in: ${cli}`);
  assert.ok(cli.includes('--abr-sensitivity conservative'), `expected --abr-sensitivity conservative in: ${cli}`);
  assert.ok(cli.includes('--web-screen-mode main'), `expected --web-screen-mode main in: ${cli}`);
  assert.ok(cli.includes('--web-require-approval'), `expected --web-require-approval in: ${cli}`);
}
console.log('PASS [4/5]: admin.html CLI builder emits all new feature flags cleanly');

// =========================================================================
// 5. Static Objective-C Selector Integrity Check on macos/bridge.m (BUG-B2-1 Guard)
// =========================================================================
{
  const bridgeSrc = fs.readFileSync(path.join(repoRoot, 'macos/bridge.m'), 'utf8');
  const definedSelectors = new Set();
  // Collect every `- (ret)selPart1:(T)a selPart2:(T)b` method definition (including multi-line headers) & @property accessor
  const propSetters = new Set();
  const nonVoidMethods = new Set();
  for (const m of bridgeSrc.matchAll(/^[+-]\s*\(([^)]+)\)\s*([^{;]+)/gm)) {
    const retType = m[1].trim();
    const sig = m[2].trim();
    let sel = '';
    if (sig.includes(':')) {
      const parts = [...sig.matchAll(/([A-Za-z_]\w*)\s*:/g)].map((x) => x[1] + ':');
      if (parts.length > 0) sel = parts.join('');
    } else {
      sel = sig.split(/\s+/)[0] || '';
    }
    if (sel) {
      definedSelectors.add(sel);
      if (retType !== 'void') nonVoidMethods.add(sel);
    }
  }
  for (const m of bridgeSrc.matchAll(/@property\s*\([^)]*\)\s*[^;]*?\*?(\w+)\s*;/g)) {
    const p = m[1];
    const setter = 'set' + p[0].toUpperCase() + p.slice(1) + ':';
    definedSelectors.add(p);
    definedSelectors.add(setter);
    propSetters.add(setter);
  }
  const setterCollisions = [...propSetters].filter((s) => nonVoidMethods.has(s));
  assert.deepEqual(
    setterCollisions,
    [],
    `macos/bridge.m has non-void method(s) colliding with @property void setter(s): ${setterCollisions.join(', ')}`
  );
  // NSObject / standard Foundation / AppKit / ScreenCaptureKit / CoreGraphics inherited selectors
  for (const std of [
    'init', 'dealloc', 'class', 'description', 'respondsToSelector:',
    'new', 'alloc', 'copy', 'mutableCopy', 'retain', 'release', 'autorelease',
    'displayID', 'settings', 'applySettings:',
  ]) {
    definedSelectors.add(std);
  }
  // Check every internal receiver message send (`self`, `strongSelf`, `ctrl`, `strongCtrl`, `laterCtrl`, `vd`, `self.virtualDisplay`)
  const missingSelectors = [];
  for (const m of bridgeSrc.matchAll(
    /\[\s*(?:self|strongSelf|ctrl|strongCtrl|laterCtrl|vd|self\.virtualDisplay)\s+([A-Za-z_]\w*(?::[^\[\];]*?)?)\s*\]/g
  )) {
    const body = m[1].trim();
    let sel;
    if (body.includes(':')) {
      // Extract selector labels (identifiers immediately before `:`, skipping ternary `? a : b`)
      const cleaned = body.replace(/@"[^"]*"/g, '""').replace(/\([^()]*\)/g, '()');
      const parts = [...cleaned.matchAll(/(?:^|\s)([A-Za-z_]\w*)\s*:/g)].map((x) => x[1] + ':');
      sel = parts.join('');
    } else {
      sel = body.split(/\s+/)[0];
    }
    if (sel && !definedSelectors.has(sel)) {
      missingSelectors.push(sel);
    }
  }
  assert.deepEqual(
    missingSelectors,
    [],
    `macos/bridge.m sends undeclared Objective-C selector(s) to internal receivers: ${missingSelectors.join(', ')}`
  );
  // Iter-7 P2-B1 static guard: every CGVirtualDisplay terminationHandler must verify `_paused` and `displayObj != display`
  const termHandlers = [...bridgeSrc.matchAll(/terminationHandler:\^\(id display, NSError \* _Nullable error\) \{[\s\S]*?\}\];/g)];
  assert.equal(termHandlers.length, 2, 'expected 2 CGVirtualDisplay terminationHandler blocks in macos/bridge.m');
  for (const m of termHandlers) {
    assert.ok(m[0].includes('_paused'), 'Iter-7 P2-B1: terminationHandler must ignore callbacks while _paused');
    assert.ok(m[0].includes('displayObj != display'), 'Iter-7 P2-B1: terminationHandler must verify display identity');
  }
  // Guard: updateShowCursor: must restart SCStream instead of relying on SCStream updateConfiguration: (macOS ScreenCaptureKit ignores showsCursor toggles in updateConfiguration:)
  const updateShowCursorMatch = bridgeSrc.match(/- \(BOOL\)updateShowCursor:\(BOOL\)show \{[\s\S]*?\n\}/);
  assert.ok(updateShowCursorMatch, 'updateShowCursor: method must exist in macos/bridge.m');
  const updateShowCursorCode = updateShowCursorMatch[0].replace(/\/\/[^\n]*/g, '');
  assert.ok(
    updateShowCursorCode.includes('stopScreenCaptureKitLocked') && updateShowCursorCode.includes('startScreenCaptureKitLockedWithWidth:'),
    'updateShowCursor: must restart SCStream to apply showsCursor reliably on macOS'
  );
  assert.ok(
    !updateShowCursorCode.includes('updateConfiguration:'),
    'updateShowCursor: must not rely on SCStream updateConfiguration: for showsCursor'
  );
  // Guard: virtual display mode selection must fall back to child helper when CGDisplayCopyAllDisplayModes returns NULL,
  // compute orientation-aware sizeInMillimeters, and log SCStreamFrameInfoScaleFactor for HiDPI diagnostics.
  assert.ok(
    bridgeSrc.includes('id_spawn_set_display_mode_helper') && bridgeSrc.includes('--internal-macos-set-display-mode'),
    'macos/bridge.m must fall back to child display-mode helper when in-process CGDisplayCopyAllDisplayModes returns NULL'
  );
  assert.ok(
    bridgeSrc.includes('SCStreamFrameInfoScaleFactor') && bridgeSrc.includes('scaleFactor=%.2f'),
    'macos/bridge.m sc_frame_geometry must inspect and log SCStreamFrameInfoScaleFactor'
  );
  assert.ok(
    !bridgeSrc.includes('CGSizeMake(197.0, 148.0)'),
    'macos/bridge.m must compute orientation-aware sizeInMillimeters instead of hardcoded landscape 197x148mm'
  );
  // Guard: standalone ephemeral virtual display & AX window routing symbols must remain wired cleanly
  for (const sym of [
    'id_macos_virtual_display_create',
    'id_macos_virtual_display_destroy',
    'id_macos_list_windows_json',
    'id_macos_move_window',
    '_AXUIElementGetWindow',
    'AXManualAccessibility',
  ]) {
    assert.ok(
      bridgeSrc.includes(sym),
      `macos/bridge.m missing required virtual display / AX window routing symbol: ${sym}`
    );
  }
  // Guard: no duplicate exported C bridge function definitions (`id_macos_*`)
  const cFuncCounts = new Map();
  for (const m of bridgeSrc.matchAll(/^(?:void|int32_t|uint32_t|void\s*\*)\s*\*?\s*(id_macos_\w+)\s*\(/gm)) {
    const fn = m[1];
    cFuncCounts.set(fn, (cFuncCounts.get(fn) || 0) + 1);
  }
  const dupCFuncs = [...cFuncCounts.entries()].filter(([, n]) => n > 1).map(([k]) => k);
  assert.deepEqual(
    dupCFuncs,
    [],
    `macos/bridge.m has duplicate exported C function definition(s): ${dupCFuncs.join(', ')}`
  );
  // Guard: JSON boolean fields in macos/bridge.m must box @YES/@NO (NOT C int `@(expr > 0)`)
  assert.ok(
    bridgeSrc.includes('@"is_floating": ((layer > 0) ? @YES : @NO)'),
    'macos/bridge.m must emit true JSON booleans (@YES/@NO) for is_floating'
  );
  // Guard: sub-60fps VSync phase-slip helper & 8s IPPP keyframe cadence must remain intact
  assert.ok(
    bridgeSrc.includes('id_sc_min_frame_interval(uint32_t fps)')
      && bridgeSrc.includes('MAX(30, fpsVal * 8)'),
    'macos/bridge.m must preserve VSync headroom helper and 8s IPPP keyframe interval'
  );

  // Guard (v0.3.8/v0.3.9 regressions):
  // 1) Never pre-block ScreenCaptureKit on buggy CGPreflightScreenCaptureAccess() (false-negatives on macOS 14/15 CLI)
  const startScMatch = bridgeSrc.match(/- \(BOOL\)startScreenCaptureKitLockedWithWidth:[\s\S]*?\n\}\n\n- \(BOOL\)ensureVirtualDisplayOnlineForceRecreate:/);
  assert.ok(startScMatch, 'startScreenCaptureKitLockedWithWidth: method must exist in macos/bridge.m');
  const startScCode = startScMatch[0].replace(/\/\/[^\n]*/g, '');
  assert.ok(
    !startScCode.includes('CGPreflightScreenCaptureAccess'),
    'startScreenCaptureKitLockedWithWidth: must NEVER gate on CGPreflightScreenCaptureAccess() (false-negative on macOS 14/15 CLI)'
  );
  assert.ok(
    startScCode.includes('error.code == -3801') && startScCode.includes('gLastScreenCaptureDenied'),
    'startScreenCaptureKitLockedWithWidth: must detect real SCStreamErrorUserDeclined (-3801)'
  );
  assert.ok(
    startScCode.includes('sc_virtual_display_placeholder')
      && startScCode.includes('kCVPixelFormatType_32BGRA')
      && startScCode.includes('startCoreGraphicsFallbackLockedWithFilter:'),
    'startScreenCaptureKitLockedWithWidth: must filter Intel 1x1 placeholders and keep 3-tier capture fallback'
  );
  assert.ok(
    startScCode.includes('scheduleCaptureRestartAfterMs:120 targetW:0 targetH:0 attempt:0'),
    'sc_first_frame_watchdog must escalate with attempt:0 so it never recreates online CGVirtualDisplay or flickers main screen'
  );

  // 2) Never re-apply CGVirtualDisplay mode when display is already online at matching geometry (prevents Intel main-screen flicker)
  const ensureVdMatch = bridgeSrc.match(/- \(BOOL\)ensureVirtualDisplayOnlineForceRecreate:\(BOOL\)forceRecreate \{[\s\S]*?\n\}\n\n- \(void\)scheduleCaptureRestartAfterMs:/);
  assert.ok(ensureVdMatch, 'ensureVirtualDisplayOnlineForceRecreate: method must exist');
  assert.ok(
    ensureVdMatch[0].includes('sameDims && self.virtualDisplay.hiDPI == self.hiDPI')
      && ensureVdMatch[0].includes('return YES;'),
    'ensureVirtualDisplayOnlineForceRecreate: must skip applyWidth:height: when display is already online at requested size/HiDPI'
  );

  // 3) Restart scheduler must have a hard retry bound and stop immediately on Screen Recording denial
  const restartMatch = bridgeSrc.match(/- \(void\)scheduleCaptureRestartAfterMs:\(int64_t\)delayMs targetW:\(uint32_t\)targetW targetH:\(uint32_t\)targetH attempt:\(int\)attempt \{[\s\S]*?\n\}\n\n- \(void\)scheduleCaptureRestartAfterMs:\(int64_t\)delayMs targetW:/);
  assert.ok(restartMatch, 'scheduleCaptureRestartAfterMs: must exist');
  assert.ok(
    restartMatch[0].includes('gLastScreenCaptureDenied') && restartMatch[0].includes('attempt >= 6'),
    'scheduleCaptureRestartAfterMs: must stop on permission denial and cap retries to prevent infinite flicker loops'
  );

  // 4) updateStreamFps: must declare effMaxEdge before calling fit_capture_to_sc_frame (prevents macOS clang compile break)
  const updateFpsMatch = bridgeSrc.match(/- \(BOOL\)updateStreamFps:[\s\S]*?\n\}\n\n- \(BOOL\)updateShowCursor:/);
  assert.ok(updateFpsMatch, 'updateStreamFps: must exist');
  assert.ok(
    updateFpsMatch[0].includes('__block uint32_t effMaxEdge')
      && updateFpsMatch[0].includes('fit_capture_to_sc_frame(&cfgW, &cfgH, cachedScFrame, self.hiDPI, effMaxEdge)'),
    'updateStreamFps: must declare __block uint32_t effMaxEdge before calling fit_capture_to_sc_frame'
  );

  // 5) Permission probe/request & padding-heal symbols must remain wired
  for (const sym of [
    'id_macos_probe_screen_capture_permission',
    'id_macos_request_permission',
    'id_macos_capture_display_bounds',
    'fit_capture_to_sc_frame',
    'sc_padding_heal',
    'CGDisplayStreamCreateWithDispatchQueue',
    'SCScreenshotManager',
  ]) {
    assert.ok(bridgeSrc.includes(sym), `macos/bridge.m missing required reliability symbol: ${sym}`);
  }

  // 6) Cross-platform Windows clippy guard: Unix-only canal write helpers in wifi.rs must stay #[cfg(not(windows))]
  const wifiSrc = fs.readFileSync(path.join(repoRoot, 'src/transport/wifi.rs'), 'utf8');
  assert.ok(
    /#\[cfg\(not\(windows\)\)\]\s*\nuse crate::protocol::framing::\{write_canal_block, write_canal_parts\};/.test(wifiSrc),
    'src/transport/wifi.rs must gate write_canal_block/write_canal_parts under #[cfg(not(windows))] to keep Windows clippy clean'
  );
}
console.log('PASS [5/5]: macos/bridge.m static Objective-C selector & regression guardrails verified');

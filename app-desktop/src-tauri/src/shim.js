// Orca Rust Desktop (Fase 4) — window.api shim.
// Injected by the Rust shell before any renderer code runs.
// It stands in for the Electron preload bridge: every
// window.api.<domain>.<method>(...args) call is forwarded to
// the Rust side as ipc_invoke(path, args); event-style
// methods (on*) subscribe to Tauri events the Rust side
// emits as "ipc_event" with { path, args } payloads.
// Sync boot values (platform, settings snapshot) are baked
// in by the shell — they are the only synchronous reads the
// preload performs (platform.get, settings getSync).
(function () {
  const boot = /*__BOOT__*/ null;
  if (!boot) return;
  const core = window.__TAURI__ && window.__TAURI__.core;
  const eventApi = window.__TAURI__ && window.__TAURI__.event;
  if (!core) return;

  const listeners = new Map(); // path -> Set<callback>
  if (eventApi) {
    eventApi.listen('ipc_event', (event) => {
      const payload = event && event.payload;
      if (!payload || !payload.path) return;
      const set = listeners.get(payload.path);
      if (set) for (const cb of [...set]) { try { cb(...(payload.args || [])); } catch (e) { /* renderer-side */ } }
    });
  }

  function dispatch(path, args) {
    if (path === 'platform.get') return boot.platform;
    if (path === 'settings.getSync') return boot.settings;
    if (path === 'ui.getZoomLevel') return 0;
    const last = path.slice(path.lastIndexOf('.') + 1);
    if (/^on[A-Z]/.test(last) && typeof args[0] === 'function') {
      let set = listeners.get(path);
      if (!set) { set = new Set(); listeners.set(path, set); }
      set.add(args[0]);
      return function unsubscribe() { set.delete(args[0]); };
    }
    return core.invoke('ipc_invoke', { path, args });
  }

  function makeNode(path) {
    const fn = function () {};
    return new Proxy(fn, {
      get(_target, prop) {
        if (prop === Symbol.toPrimitive) return () => '';
        if (prop === 'then') return undefined;
        if (prop === 'toJSON') return () => ({});
        return makeNode(path ? path + '.' + String(prop) : String(prop));
      },
      apply(_target, _thisArg, args) {
        return dispatch(path, args);
      }
    });
  }

  try {
    Object.defineProperty(window, 'api', { value: makeNode(''), writable: false, configurable: true });
  } catch (e) {
    window.api = makeNode('');
  }

  // Debug mode: every renderer error lands in the bridge
  // log, and hard errors also ride the crash-upload
  // pipeline so they are visible without opening the app.
  function reportError(kind, message, stack) {
    try {
      core.invoke('ipc_invoke', {
        path: 'crashReports.recordRendererError',
        args: [{
          message: String(message || ''),
          errorStack: String(stack || ''),
          boundaryId: kind,
          source: 'shim-error-hook'
        }]
      });
    } catch (e) { /* never recurse */ }
  }
  window.addEventListener('error', (event) => {
    // Resource-load failures carry no message; only real
    // script errors are worth an upload.
    if (!event.message) return;
    reportError('window.error', event.message, event.error && event.error.stack);
  });
  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason;
    reportError(
      'unhandledrejection',
      (reason && reason.message) || String(reason),
      reason && reason.stack
    );
  });
  const originalConsoleError = console.error.bind(console);
  console.error = function (...parts) {
    try {
      core.invoke('ipc_invoke', {
        path: 'renderer.consoleError',
        args: [parts.map((p) => {
          try { return typeof p === 'string' ? p : JSON.stringify(p); }
          catch (e) { return String(p); }
        }).join(' ').slice(0, 2000)]
      });
    } catch (e) { /* log only */ }
    return originalConsoleError(...parts);
  };
})();

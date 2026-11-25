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
})();

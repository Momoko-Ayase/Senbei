// The page's side of `worker.js`: one compiled module, and workers that live
// for one job (a recovery) or for one scan (the probes).

let compiled = null;

/**
 * Fetch and compile the engine once. Workers instantiate this module, so none
 * of them downloads or compiles it again.
 */
export function loadEngine() {
  compiled ??= (async () => {
    const url = new URL('./pkg/senbei_wasm_bg.wasm', import.meta.url);
    try {
      return await WebAssembly.compileStreaming(fetch(url));
    } catch {
      // A server that sends the wrong content type cannot be streamed.
      const response = await fetch(url);
      if (!response.ok) throw new Error(`engine download failed (${response.status})`);
      return WebAssembly.compile(await response.arrayBuffer());
    }
  })();
  compiled.catch(() => {
    compiled = null;
  });
  return compiled;
}

/** The engine ended without an answer: a trap, or the worker itself failed. */
export class EngineStopped extends Error {
  constructor(message, trap) {
    super(message);
    this.name = 'EngineStopped';
    this.trap = trap;
  }
}

/** One worker and the requests it has not answered yet. */
class Session {
  #worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  #pending = new Map();
  #next = 1;
  #sentEngine = false;
  closed = false;

  constructor() {
    this.#worker.onmessage = (event) => {
      const message = event.data;
      const pending = this.#pending.get(message.id);
      if (!pending) return;
      if (message.type === 'done') {
        this.#pending.delete(message.id);
        pending.resolve(message);
      } else if (message.type === 'error') {
        this.#pending.delete(message.id);
        pending.reject(
          message.trap ? new EngineStopped(message.message, true) : new Error(message.message),
        );
      } else {
        pending.on?.(message);
      }
    };
    this.#worker.onerror = (event) => {
      event.preventDefault?.();
      this.#fail(new EngineStopped(event.message || 'worker failed', false));
    };
    this.#worker.onmessageerror = () => {
      this.#fail(new EngineStopped('worker reply could not be read', false));
    };
  }

  #fail(error) {
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
    this.close();
  }

  /** Send one request. `on` receives the replies that precede the last one. */
  async request(message, on) {
    const wasm = await loadEngine();
    if (this.closed) throw new EngineStopped('worker was closed', false);
    const id = this.#next;
    this.#next += 1;
    // The worker instantiates the module from its first request.
    const first = !this.#sentEngine;
    this.#sentEngine = true;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject, on });
      this.#worker.postMessage(first ? { ...message, id, wasm } : { ...message, id });
    });
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.#worker.terminate();
    this.#fail(new EngineStopped('worker was closed', false));
  }
}

/**
 * Run one recovery in a worker of its own.
 *
 * `request` is `{ op: 'pe' | 'so' | 'metadata', input, lang, ... }`. `on.step`
 * is called as each step starts and `on.result` once the outcome is known,
 * before its digests are. Resolves to `{ op, info, image, embedded,
 * moduleBytes, identity }`, `op` being the job that ran. Rejects with
 * [`EngineStopped`] when the engine ended without an answer. `signal` ends the
 * worker and rejects.
 */
export async function runJob(request, on = {}, signal) {
  const session = new Session();
  const abort = () => session.close();
  signal?.addEventListener('abort', abort, { once: true });
  const outcome = { op: request.op, info: null, image: null, embedded: null, moduleBytes: null, identity: null };
  try {
    if (signal?.aborted) throw new EngineStopped('cancelled', false);
    await session.request(request, (message) => {
      if (message.type === 'step') {
        on.step?.(message);
      } else if (message.type === 'result') {
        outcome.info = message.info;
        outcome.image = message.image;
        outcome.embedded = message.embedded;
        outcome.moduleBytes = message.module;
        on.result?.(outcome);
      } else if (message.type === 'identity') {
        outcome.identity = {
          input: message.input,
          image: message.image,
          embedded: message.embedded,
          companion: message.companion ?? null,
        };
      }
    });
    return outcome;
  } finally {
    signal?.removeEventListener('abort', abort);
    session.close();
  }
}

/** A probe above this size leaves its worker holding that much memory. */
const RESTART_AFTER_BYTES = 32 * 1024 * 1024;

/**
 * The scan's probes. One worker answers them in turn; it is replaced after a
 * trap and after a large library probe, whose memory it would otherwise keep.
 */
export class Prober {
  #session = null;

  #open() {
    if (!this.#session || this.#session.closed) this.#session = new Session();
    return this.#session;
  }

  async #ask(message) {
    try {
      return await this.#open().request(message);
    } catch (error) {
      this.close();
      throw error;
    }
  }

  /** What a file's first bytes are: `{ kind, profile }`. */
  prefix(bytes) {
    return this.#ask({ op: 'prefix', bytes });
  }

  /** Probe a whole AArch64 library; resolves to its probe profile. */
  async library(input, size) {
    const reply = await this.#ask({ op: 'probe-so', input });
    if (size > RESTART_AFTER_BYTES) this.close();
    return reply.profile;
  }

  /** `[package, version]` from a manifest, or `null`. */
  async manifest(bytes, truncated) {
    return (await this.#ask({ op: 'manifest', bytes, truncated })).identity;
  }

  /**
   * The engine's message for a package refused over an entry name that leaves
   * it: `{ text, local, lang }`, with `local` worded in `lang`.
   */
  async unsafeEntry(packagePath, lang) {
    const reply = await this.#ask({ op: 'unsafe-entry', package: packagePath, lang });
    return { ...reply.message, lang };
  }

  close() {
    this.#session?.close();
    this.#session = null;
  }
}

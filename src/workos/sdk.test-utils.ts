import { WorkOS } from '@workos-inc/node';
import type { createServer } from '../core/index.js';

// An @workos-inc/node client whose requests are served in-process by `app` — no port, no
// listener — so a test can assert what the real SDK makes of an emulator response (which
// exception class, which fields). Bun's `typeof fetch` carries `preconnect`, hence the
// Object.assign rather than a bare arrow.
export function sdkClient(app: ReturnType<typeof createServer>['app'], apiKey: string): WorkOS {
  const fetchFn: typeof fetch = Object.assign(
    async (input: Request | string | URL, init?: RequestInit) => app.request(input, init),
    { preconnect: fetch.preconnect },
  );
  return new WorkOS({ apiKey, apiHostname: 'emulate.test', https: false, maxRetries: 0, fetchFn });
}

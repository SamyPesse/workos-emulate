import { describe, expect, it } from 'bun:test';
import { createEmulator, type Emulator } from './index.js';

async function request(emulator: Emulator, apiKey = emulator.apiKey): Promise<Response> {
  const response = await fetch(`${emulator.url}/organizations`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  await response.text();
  return response;
}

describe('request budgets', () => {
  it('retains the default budget and throttles exhausted requests', async () => {
    const emulator = await createEmulator({ port: 0 });
    try {
      for (let count = 0; count < 999; count++) {
        const response = await request(emulator);
        expect(response.status).toBe(200);
        expect(response.headers.get('X-RateLimit-Limit')).toBe('1000');
      }
      const response = await request(emulator);
      expect(response.status).toBe(429);
      expect(response.headers.get('X-RateLimit-Remaining')).toBe('0');
      expect(Number(response.headers.get('Retry-After'))).toBeGreaterThan(0);
    } finally {
      await emulator.close();
    }
  });

  it('uses the configured budget while keeping API keys isolated', async () => {
    const emulator = await createEmulator({
      port: 0,
      requestsPerMinute: 3,
      seed: {
        apiKeys: {
          sk_test_first: { environment: 'test' },
          sk_test_second: { environment: 'test' },
        },
      },
    });
    try {
      expect((await request(emulator, 'sk_test_first')).status).toBe(200);
      const available = await request(emulator, 'sk_test_first');
      expect(available.status).toBe(200);
      expect(available.headers.get('X-RateLimit-Limit')).toBe('3');
      expect(available.headers.get('X-RateLimit-Remaining')).toBe('1');
      const exhausted = await request(emulator, 'sk_test_first');
      expect(exhausted.status).toBe(429);
      expect(exhausted.headers.get('X-RateLimit-Remaining')).toBe('0');
      expect(Number(exhausted.headers.get('Retry-After'))).toBeGreaterThan(0);
      const independent = await request(emulator, 'sk_test_second');
      expect(independent.status).toBe(200);
      expect(independent.headers.get('X-RateLimit-Remaining')).toBe('2');
    } finally {
      await emulator.close();
    }
  });

  it('allows integration suites to exceed the default budget', async () => {
    const emulator = await createEmulator({ port: 0, requestsPerMinute: 10_000 });
    try {
      for (let count = 0; count < 1000; count++) {
        const response = await request(emulator);
        expect(response.status).toBe(200);
      }
      const response = await request(emulator);
      expect(response.status).toBe(200);
      expect(response.headers.get('X-RateLimit-Limit')).toBe('10000');
      expect(response.headers.get('X-RateLimit-Remaining')).toBe('8999');
    } finally {
      await emulator.close();
    }
  });

  it.each([0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    'rejects invalid request budget %s before starting the server',
    async (requestsPerMinute) => {
      await expect(createEmulator({ port: 0, requestsPerMinute })).rejects.toThrow(
        'requestsPerMinute must be a positive safe integer',
      );
    },
  );
});

import { describe, it, expect, beforeEach } from 'bun:test';
import { createServer, type ApiKeyMap } from '../../core/index.js';
import { workosPlugin } from '../index.js';
import { sdkClient } from '../sdk.test-utils.js';

const apiKeys: ApiKeyMap = { sk_test_org: { environment: 'test' } };
const headers = { Authorization: 'Bearer sk_test_org', 'Content-Type': 'application/json' };

function createTestApp() {
  return createServer(workosPlugin, { port: 0, baseUrl: 'http://localhost:0', apiKeys });
}

describe('Data Integrations routes', () => {
  let app: ReturnType<typeof createTestApp>['app'];

  beforeEach(() => {
    app = createTestApp().app;
  });

  const req = (path: string, init?: RequestInit) => app.request(path, { headers, ...init });
  const json = (res: Response) => res.json() as Promise<any>;

  it('authorize redirects with code', async () => {
    const res = await app.request(
      '/data-integrations/salesforce/authorize?redirect_uri=http://localhost:3000/callback&state=xyz',
      { redirect: 'manual' },
    );
    expect(res.status).toBe(302);
    const location = res.headers.get('Location')!;
    expect(location).toContain('code=');
    expect(location).toContain('state=xyz');
  });

  it('authorize rejects missing redirect_uri', async () => {
    const res = await app.request('/data-integrations/salesforce/authorize');
    expect(res.status).toBe(400);
  });

  it('authorize rejects non-localhost redirect_uri', async () => {
    const res = await app.request('/data-integrations/salesforce/authorize?redirect_uri=https://evil.com/callback');
    expect(res.status).toBe(400);
  });

  it('exchanges code for token', async () => {
    // First authorize to get a code
    const authRes = await app.request(
      '/data-integrations/salesforce/authorize?redirect_uri=http://localhost:3000/callback',
      { redirect: 'manual' },
    );
    const location = authRes.headers.get('Location')!;
    const code = new URL(location).searchParams.get('code')!;

    // Exchange code
    const tokenRes = await req('/data-integrations/salesforce/token', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
    expect(tokenRes.status).toBe(200);
    const data = await json(tokenRes);
    expect(data.access_token).toBeDefined();
    expect(data.token_type).toBe('bearer');
  });

  it('rejects invalid code', async () => {
    const res = await req('/data-integrations/salesforce/token', {
      method: 'POST',
      body: JSON.stringify({ code: 'invalid_code' }),
    });
    expect(res.status).toBe(400);
  });

  it('rejects code reuse', async () => {
    const authRes = await app.request(
      '/data-integrations/github/authorize?redirect_uri=http://localhost:3000/callback',
      { redirect: 'manual' },
    );
    const code = new URL(authRes.headers.get('Location')!).searchParams.get('code')!;

    // First use succeeds
    await req('/data-integrations/github/token', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });

    // Second use fails
    const res = await req('/data-integrations/github/token', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
    expect(res.status).toBe(400);
  });

  describe('connected-account access tokens', () => {
    let userId: string;

    beforeEach(async () => {
      const user = await json(
        await req('/user_management/users', {
          method: 'POST',
          body: JSON.stringify({ email: 'pipes@acme.test' }),
        }),
      );
      userId = user.id;
    });

    async function importAccount(body: Record<string, unknown>, organizationId?: string) {
      const query = organizationId ? `?organization_id=${organizationId}` : '';
      const res = await req(`/user_management/users/${userId}/connected_accounts/github${query}`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      expect(res.status).toBe(201);
    }

    const token = (body: Record<string, unknown>) =>
      req('/data-integrations/github/token', { method: 'POST', body: JSON.stringify(body) });

    it('returns imported credentials in the shape decoded by @workos-inc/node', async () => {
      const expiresAt = new Date(Date.now() + 3_600_000);
      await importAccount({
        access_token: 'github_imported_token',
        refresh_token: 'private_refresh_token',
        expires_at: expiresAt.toISOString(),
        scopes: ['repo', 'user:email'],
      });

      const workos = sdkClient(app, 'sk_test_org');
      expect(await workos.pipes.getAccessToken({ provider: 'github', userId })).toEqual({
        active: true,
        accessToken: {
          object: 'access_token',
          accessToken: 'github_imported_token',
          expiresAt,
          scopes: ['repo', 'user:email'],
          missingScopes: [],
        },
      });
    });

    it('keeps user, provider, and organization scopes separate', async () => {
      const workos = sdkClient(app, 'sk_test_org');
      const org = await workos.organizations.createOrganization({ name: 'Acme' });
      const otherOrg = await workos.organizations.createOrganization({ name: 'Other' });
      const otherUser = await workos.userManagement.createUser({ email: 'other@acme.test' });
      await importAccount({ access_token: 'org_token' }, org.id);

      expect(await workos.pipes.getAccessToken({ provider: 'github', userId })).toEqual({
        active: false,
        error: 'not_installed',
      });

      await importAccount({ access_token: 'personal_token' });
      for (const organizationId of [undefined, null]) {
        expect(await workos.pipes.getAccessToken({ provider: 'github', userId, organizationId })).toMatchObject({
          active: true,
          accessToken: { accessToken: 'personal_token', expiresAt: null, scopes: [] },
        });
      }
      expect(await workos.pipes.getAccessToken({ provider: 'github', userId, organizationId: org.id })).toMatchObject({
        active: true,
        accessToken: { accessToken: 'org_token' },
      });
      for (const options of [
        { provider: 'github', userId: otherUser.id },
        { provider: 'slack', userId },
        { provider: 'github', userId, organizationId: otherOrg.id },
      ]) {
        expect(await workos.pipes.getAccessToken(options)).toEqual({ active: false, error: 'not_installed' });
      }
    });

    it('returns not_installed for missing and disconnected accounts', async () => {
      const workos = sdkClient(app, 'sk_test_org');
      expect(await workos.pipes.getAccessToken({ provider: 'github', userId })).toEqual({
        active: false,
        error: 'not_installed',
      });
      await importAccount({ access_token: 'disconnected_token' });
      await req(`/user_management/users/${userId}/connected_accounts/github`, { method: 'DELETE' });
      expect(await workos.pipes.getAccessToken({ provider: 'github', userId })).toEqual({
        active: false,
        error: 'not_installed',
      });
    });

    it.each([
      { state: 'needs_reauthorization', access_token: 'stale_token' },
      { state: 'connected' },
      { access_token: 'expired_token', expires_at: '2000-01-01T00:00:00.000Z' },
      { access_token: 'expired_token', refresh_token: 'refresh_token', expires_at: '2000-01-01T00:00:00.000Z' },
      { refresh_token: 'refresh_token' },
    ])('requires reauthorization when imported credentials are unusable: %j', async (account) => {
      await importAccount(account);
      const workos = sdkClient(app, 'sk_test_org');
      expect(await workos.pipes.getAccessToken({ provider: 'github', userId })).toEqual({
        active: false,
        error: 'needs_reauthorization',
      });
    });

    it('rejects nonexistent users and organizations', async () => {
      expect((await token({ user_id: 'user_missing' })).status).toBe(404);
      expect((await token({ user_id: userId, organization_id: 'org_missing' })).status).toBe(404);
    });

    it.each(['', 123, null])('rejects invalid user IDs: %j', async (userId) => {
      expect((await token({ user_id: userId })).status).toBe(422);
    });

    it.each(['', 123])('rejects invalid organization IDs: %j', async (organizationId) => {
      expect((await token({ user_id: userId, organization_id: organizationId })).status).toBe(422);
    });

    it('requires an API key', async () => {
      const res = await app.request('/data-integrations/github/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId }),
      });
      expect(res.status).toBe(401);
    });
  });
});

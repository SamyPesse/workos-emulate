import { type RouteContext, parseJsonBody, WorkOSApiError, notFound, validationError } from '../../core/index.js';
import { getWorkOSStore } from '../store.js';
import { assertAllowedRedirectUri, generateVerificationToken, expiresIn, isExpired } from '../helpers.js';

export function dataIntegrationRoutes(ctx: RouteContext): void {
  const { app, store } = ctx;
  const ws = getWorkOSStore(store);

  // Authorize (public endpoint — no auth required)
  app.get('/data-integrations/:slug/authorize', (c) => {
    const slug = c.req.param('slug');
    const url = new URL(c.req.url);
    const redirectUri = url.searchParams.get('redirect_uri');
    const state = url.searchParams.get('state') ?? null;

    if (!redirectUri) {
      throw new WorkOSApiError(400, 'redirect_uri is required', 'invalid_request');
    }
    assertAllowedRedirectUri(redirectUri, store);

    const code = generateVerificationToken();
    ws.dataIntegrationAuths.insert({
      slug,
      code,
      redirect_uri: redirectUri,
      state,
      expires_at: expiresIn(10),
    });

    const redirect = new URL(redirectUri);
    redirect.searchParams.set('code', code);
    if (state) redirect.searchParams.set('state', state);

    return c.redirect(redirect.toString(), 302);
  });

  // Retrieve an imported connected-account token, or exchange a legacy authorization code.
  app.post('/data-integrations/:slug/token', async (c) => {
    const slug = c.req.param('slug');
    const body = await parseJsonBody(c);

    if (body.user_id !== undefined) {
      if (typeof body.user_id !== 'string' || !body.user_id) {
        throw validationError('user_id must be a non-empty string', [{ field: 'user_id', code: 'invalid' }]);
      }
      const organizationId = body.organization_id ?? null;
      if (organizationId !== null && (typeof organizationId !== 'string' || !organizationId)) {
        throw validationError('organization_id must be a non-empty string', [
          { field: 'organization_id', code: 'invalid' },
        ]);
      }
      if (!ws.users.get(body.user_id)) throw notFound('User');
      if (organizationId && !ws.organizations.get(organizationId)) throw notFound('Organization');

      const account = ws.connectedAccounts
        .findBy('user_id', body.user_id)
        .find((a) => a.provider === slug && a.organization_id === organizationId);
      if (!account) return c.json({ active: false, error: 'not_installed' });

      // Imported credentials are returned verbatim. Refreshing them would require contacting
      // the real provider, so expired or absent access tokens need reauthorization instead.
      if (
        account.state !== 'connected' ||
        !account.access_token ||
        (account.token_expires_at && isExpired(account.token_expires_at))
      ) {
        return c.json({ active: false, error: 'needs_reauthorization' });
      }

      return c.json({
        active: true,
        access_token: {
          object: 'access_token',
          access_token: account.access_token,
          expires_at: account.token_expires_at,
          scopes: account.scopes,
          missing_scopes: [],
        },
      });
    }

    const code = body.code as string | undefined;

    if (!code) {
      throw new WorkOSApiError(400, 'code is required', 'invalid_request');
    }

    const auth = ws.dataIntegrationAuths.findOneBy('code', code);
    if (!auth || auth.slug !== slug) {
      throw new WorkOSApiError(400, 'Invalid authorization code', 'invalid_grant');
    }

    if (isExpired(auth.expires_at)) {
      ws.dataIntegrationAuths.delete(auth.id);
      throw new WorkOSApiError(400, 'Authorization code has expired', 'invalid_grant');
    }

    ws.dataIntegrationAuths.delete(auth.id);

    return c.json({
      access_token: `di_mock_${slug}_${generateVerificationToken().slice(0, 8)}`,
      token_type: 'bearer',
      expires_in: 3600,
    });
  });
}

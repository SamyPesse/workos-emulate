import { beforeEach, describe, expect, it } from 'bun:test';
import { createServer } from '../../core/index.js';
import { workosPlugin } from '../index.js';

const headers = { authorization: 'Bearer sk_test_groups_authz', 'content-type': 'application/json' };

describe('Native group authorization', () => {
  let app: ReturnType<typeof createServer>['app'];
  beforeEach(() => {
    app = createServer(workosPlugin, { apiKeys: { sk_test_groups_authz: { environment: 'test' } } }).app;
  });
  const request = (path: string, method = 'GET', body?: unknown) =>
    app.request(path, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  async function create(path: string, body: unknown) {
    const response = await request(path, 'POST', body);
    expect(response.status).toBe(201);
    return response.json() as Promise<any>;
  }
  async function setup() {
    const organization = await create('/organizations', { name: 'Group authorization' });
    const user = await create('/user_management/users', { email: 'writer@example.com' });
    const membership = await create('/user_management/organization_memberships', {
      organization_id: organization.id,
      user_id: user.id,
      role_slug: 'member',
    });
    await create('/authorization/permissions', {
      slug: 'repository:read',
      name: 'Read',
      resource_type_slug: 'repository',
    });
    const role = await create('/authorization/roles', {
      slug: 'repository-reader',
      name: 'Reader',
      resource_type_slug: 'repository',
    });
    await request('/authorization/roles/repository-reader/permissions', 'PUT', { permissions: ['repository:read'] });
    const resource = await create('/authorization/resources', {
      organization_id: organization.id,
      resource_type_slug: 'repository',
      external_id: 'repo',
      name: 'Repository',
    });
    const group = await create(`/organizations/${organization.id}/groups`, { name: 'Readers' });
    await request(`/organizations/${organization.id}/groups/${group.id}/organization-memberships`, 'POST', {
      organization_membership_id: membership.id,
    });
    const path = `/authorization/groups/${group.id}/role_assignments`;
    const assignment = await create(path, { role_slug: role.slug, resource_id: resource.id });
    const check = async (resourceId = resource.id) => {
      const response = await request(`/authorization/organization_memberships/${membership.id}/check`, 'POST', {
        permission_slug: 'repository:read',
        resource_id: resourceId,
      });
      expect(response.status).toBe(200);
      return ((await response.json()) as { authorized: boolean }).authorized;
    };
    return { organization, membership, role, resource, group, path, assignment, check };
  }

  it('grants scoped access, lists derived assignments, and revokes when group membership is removed', async () => {
    const { organization, membership, resource, group, path, assignment, check } = await setup();
    expect(await check()).toBe(true);
    const other = await create('/authorization/resources', {
      organization_id: organization.id,
      resource_type_slug: 'repository',
      external_id: 'other',
      name: 'Other',
    });
    expect(await check(other.id)).toBe(false);
    const child = await create('/authorization/resources', {
      organization_id: organization.id,
      resource_type_slug: 'document',
      external_id: 'child',
      name: 'Child',
      parent_resource_id: resource.id,
    });
    expect(await check(child.id)).toBe(true);

    expect(((await (await request(path)).json()) as any).data[0]).toMatchObject({
      id: assignment.id,
      object: 'group_role_assignment',
      group_id: group.id,
      role: { slug: 'repository-reader' },
      resource: { id: resource.id },
    });
    expect((await request(`${path}/${assignment.id}`)).status).toBe(200);
    const memberPath = `/authorization/organization_memberships/${membership.id}/role_assignments`;
    const derived = ((await (await request(`${memberPath}?resource_id=${resource.id}`)).json()) as any).data;
    expect(derived).toHaveLength(1);
    expect(derived[0]).toMatchObject({
      organization_membership_id: membership.id,
      source: { type: 'group', group_role_assignment_id: assignment.id },
    });
    expect(((await (await request(`${memberPath}?resource_id=${other.id}`)).json()) as any).data).toEqual([]);
    const resourcePath = `/authorization/organizations/${organization.id}/resources/repository/repo/role_assignments`;
    expect(((await (await request(resourcePath)).json()) as any).data[0].source.type).toBe('group');
    const resources = await request(
      `/authorization/organization_memberships/${membership.id}/resources?permission_slug=repository:read&parent_resource_type_slug=organization&parent_resource_external_id=${organization.id}`,
    );
    expect(((await resources.json()) as any).data.map((row: any) => row.id)).toEqual([resource.id]);
    await request(
      `/organizations/${organization.id}/groups/${group.id}/organization-memberships/${membership.id}`,
      'DELETE',
    );
    expect(await check()).toBe(false);
  });

  it('rejects foreign subjects, duplicate grants, and mismatched assignment IDs', async () => {
    const { resource, path, assignment, check } = await setup();
    expect((await request(path, 'POST', { role_slug: 'repository-reader', resource_id: resource.id })).status).toBe(
      409,
    );
    const foreign = await create('/organizations', { name: 'Other organization' });
    const foreignGroup = await create(`/organizations/${foreign.id}/groups`, { name: 'Foreign' });
    const foreignPath = `/authorization/groups/${foreignGroup.id}/role_assignments`;
    expect(
      (await request(foreignPath, 'POST', { role_slug: 'repository-reader', resource_id: resource.id })).status,
    ).toBe(404);
    expect((await request(`${foreignPath}/${assignment.id}`, 'DELETE')).status).toBe(404);
    expect(await check()).toBe(true);
    expect((await request(`${path}/${assignment.id}`, 'DELETE')).status).toBe(204);
    expect(await check()).toBe(false);
  });

  it('cascades group grants when resources, roles, or groups are deleted', async () => {
    for (const target of ['resource', 'role', 'group'] as const) {
      const { organization, role, resource, group, path, check } = await setup();
      if (target === 'resource') {
        expect((await request(`/authorization/resources/${resource.id}`, 'DELETE')).status).toBe(409);
        expect((await request(`/authorization/resources/${resource.id}?cascade_delete=true`, 'DELETE')).status).toBe(
          204,
        );
      } else if (target === 'role') {
        expect((await request(`/authorization/roles/${role.slug}`, 'DELETE')).status).toBe(204);
        expect(await check()).toBe(false);
      } else {
        expect((await request(`/organizations/${organization.id}/groups/${group.id}`, 'DELETE')).status).toBe(204);
        expect(await check()).toBe(false);
      }
      const response = await request(path);
      if (target === 'group') expect(response.status).toBe(404);
      else expect(((await response.json()) as any).data).toEqual([]);
      app = createServer(workosPlugin, { apiKeys: { sk_test_groups_authz: { environment: 'test' } } }).app;
    }
  });

  it('updates resources through SDK PATCH paths by ID and external ID, including null descriptions', async () => {
    const { organization, resource } = await setup();
    const first = await request(`/authorization/resources/${resource.id}`, 'PATCH', {
      name: 'Renamed',
      description: null,
    });
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ name: 'Renamed', description: null });
    const path = `/authorization/organizations/${organization.id}/resources/repository/repo`;
    const second = await request(path, 'PATCH', { description: 'Current description' });
    expect(second.status).toBe(200);
    expect(await second.json()).toMatchObject({ id: resource.id, name: 'Renamed', description: 'Current description' });
    expect((await request(path.replace(organization.id, 'org_foreign'), 'PATCH', { name: 'Denied' })).status).toBe(404);
  });
});

import type { Credentials } from '../../../../src/authentication/Credentials';
import { AbacStoreReader } from '../../../../src/authorization/abac/AbacStoreReader';
import type { AccessMap, PermissionSet } from '../../../../src/authorization/permissions/Permissions';
import { AccessMode } from '../../../../src/authorization/permissions/Permissions';
import type { ResourceIdentifier } from '../../../../src/http/representation/ResourceIdentifier';
import type { PodStore } from '../../../../src/identity/interaction/pod/util/PodStore';
import { SubdomainIdentifierGenerator } from '../../../../src/pods/generate/SubdomainIdentifierGenerator';
import { SuffixIdentifierGenerator } from '../../../../src/pods/generate/SuffixIdentifierGenerator';
import { PodStorageLocationStrategy } from '../../../../src/server/description/PodStorageLocationStrategy';
import { IdentifierMap, IdentifierSetMultiMap } from '../../../../src/util/map/IdentifierMap';
import { compareMaps } from '../../../util/Util';

function request(identifiers: ResourceIdentifier[]): AccessMap {
  return new IdentifierSetMultiMap(identifiers.map((id): [ResourceIdentifier, AccessMode] => [ id, AccessMode.read ]));
}

describe('An AbacStoreReader', (): void => {
  const baseUrl = 'http://example.com/';
  const admin = 'http://example.com/admin/profile/card#me';
  const alice = 'http://example.com/alice/profile/card#me';
  const resources = `${baseUrl}.abac/resources/`;

  const store = { path: `${baseUrl}.abac/` };
  const storeAcr = { path: `${baseUrl}.abac/.acr` };
  const definitions = { path: `${baseUrl}.abac/definitions/` };
  const definition = { path: `${baseUrl}.abac/definitions/role` };
  const rule = { path: `${baseUrl}.abac/rules/R001` };
  const subject = { path: `${baseUrl}.abac/subjects/alice.example/profile/card` };
  const resource = { path: `${resources}example.com/records` };
  const targets = [ store, storeAcr, definitions, definition, rule, subject, resource ];

  const all: PermissionSet = { read: true, append: true, write: true, create: true, delete: true };
  const readOnly: PermissionSet = { read: true, append: false, write: false, create: false, delete: false };
  const none: PermissionSet = { read: false, append: false, write: false, create: false, delete: false };

  // An orphaned pod exists, but its owners cannot be found.
  const owners: Record<string, string[] | undefined> = {
    [`${baseUrl}alice/`]: [ alice ],
    [`${baseUrl}bob/`]: [ 'http://example.com/bob/profile/card#me' ],
    [`${baseUrl}orphan/`]: undefined,
    'http://alice.example.com/': [ alice ],
  };
  const podStore: PodStore = {
    findByBaseUrl: async(url: string): Promise<{ id: string; accountId: string } | undefined> =>
      url in owners ? { id: url, accountId: 'account' } : undefined,
    getOwners: async(id: string): Promise<{ webId: string; visible: boolean }[] | undefined> =>
      owners[id]?.map((webId): { webId: string; visible: boolean } => ({ webId, visible: false })),
  } satisfies Partial<PodStore> as any;
  const pathPods = new PodStorageLocationStrategy(new SuffixIdentifierGenerator(baseUrl));

  it('gives the administrator full access to the whole store.', async(): Promise<void> => {
    const reader = new AbacStoreReader(baseUrl, admin, podStore, pathPods);
    const credentials = { agent: { webId: admin }};
    const result = await reader.handle({ credentials, requestedModes: request(targets) });
    compareMaps(result, new IdentifierMap(targets.map((id): [ResourceIdentifier, PermissionSet] => [ id, all ])));
  });

  it('lets anyone else only read the definitions and rules.', async(): Promise<void> => {
    const reader = new AbacStoreReader(baseUrl, admin, podStore, pathPods);
    const expected = new IdentifierMap([
      [ store, none ],
      [ storeAcr, none ],
      [ definitions, readOnly ],
      [ definition, readOnly ],
      [ rule, readOnly ],
      [ subject, none ],
      [ resource, none ],
    ]);
    const credentialSets: Credentials[] = [{ agent: { webId: alice }}, {}];
    for (const credentials of credentialSets) {
      compareMaps(await reader.handle({ credentials, requestedModes: request(targets) }), expected);
    }
  });

  it('lets a pod owner read the part of the resource assignments mirroring their pod.', async(): Promise<void> => {
    const reader = new AbacStoreReader(baseUrl, admin, podStore, pathPods);
    const own = [ 'example.com/alice', 'example.com/alice/', 'example.com/alice/records' ]
      .map((path): ResourceIdentifier => ({ path: `${resources}${path}` }));
    const others = [ '', 'example.com/', 'example.com/bob/records', 'example.com/orphan/records' ]
      .map((path): ResourceIdentifier => ({ path: `${resources}${path}` }));
    const credentials = { agent: { webId: alice }};
    const result = await reader.handle({ credentials, requestedModes: request([ ...own, ...others ]) });
    compareMaps(result, new IdentifierMap([
      ...own.map((id): [ResourceIdentifier, PermissionSet] => [ id, readOnly ]),
      ...others.map((id): [ResourceIdentifier, PermissionSet] => [ id, none ]),
    ]));
  });

  it('finds the owner of a pod on a subdomain.', async(): Promise<void> => {
    const subdomainPods = new PodStorageLocationStrategy(new SubdomainIdentifierGenerator(baseUrl));
    const reader = new AbacStoreReader(baseUrl, admin, podStore, subdomainPods);
    const own = { path: `${resources}alice.example.com/records` };
    const credentials = { agent: { webId: alice }};
    compareMaps(await reader.handle({ credentials, requestedModes: request([ own, resource ]) }), new IdentifierMap([
      [ own, readOnly ],
      [ resource, none ],
    ]));
  });

  it('can guard a store in a different container.', async(): Promise<void> => {
    const reader = new AbacStoreReader(baseUrl, admin, podStore, pathPods, 'attributes/');
    const moved = { path: `${baseUrl}attributes/rules/R001` };
    const result = await reader.handle({ credentials: {}, requestedModes: request([ rule, moved ]) });
    compareMaps(result, new IdentifierMap([[ rule, none ], [ moved, readOnly ]]));
  });
});

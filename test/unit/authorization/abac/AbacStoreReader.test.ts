import type { Credentials } from '../../../../src/authentication/Credentials';
import { AbacStoreReader } from '../../../../src/authorization/abac/AbacStoreReader';
import type { AccessMap, PermissionSet } from '../../../../src/authorization/permissions/Permissions';
import { AccessMode } from '../../../../src/authorization/permissions/Permissions';
import type { ResourceIdentifier } from '../../../../src/http/representation/ResourceIdentifier';
import { IdentifierMap, IdentifierSetMultiMap } from '../../../../src/util/map/IdentifierMap';
import { compareMaps } from '../../../util/Util';

function request(identifiers: ResourceIdentifier[]): AccessMap {
  return new IdentifierSetMultiMap(identifiers.map((id): [ResourceIdentifier, AccessMode] => [ id, AccessMode.read ]));
}

describe('An AbacStoreReader', (): void => {
  const baseUrl = 'http://example.com/';
  const admin = 'http://example.com/admin/profile/card#me';

  const store = { path: `${baseUrl}.abac/` };
  const storeAcr = { path: `${baseUrl}.abac/.acr` };
  const definitions = { path: `${baseUrl}.abac/definitions/` };
  const definition = { path: `${baseUrl}.abac/definitions/role` };
  const rule = { path: `${baseUrl}.abac/rules/R001` };
  const subject = { path: `${baseUrl}.abac/subjects/alice.example/profile/card` };
  const resource = { path: `${baseUrl}.abac/resources/records` };
  const targets = [ store, storeAcr, definitions, definition, rule, subject, resource ];

  const all: PermissionSet = { read: true, append: true, write: true, create: true, delete: true };
  const readOnly: PermissionSet = { read: true, append: false, write: false, create: false, delete: false };
  const none: PermissionSet = { read: false, append: false, write: false, create: false, delete: false };

  it('gives the administrator full access to the whole store.', async(): Promise<void> => {
    const reader = new AbacStoreReader(baseUrl, admin);
    const credentials = { agent: { webId: admin }};
    const result = await reader.handle({ credentials, requestedModes: request(targets) });
    compareMaps(result, new IdentifierMap(targets.map((id): [ResourceIdentifier, PermissionSet] => [ id, all ])));
  });

  it('lets anyone else only read the definitions and rules.', async(): Promise<void> => {
    const reader = new AbacStoreReader(baseUrl, admin);
    const expected = new IdentifierMap([
      [ store, none ],
      [ storeAcr, none ],
      [ definitions, readOnly ],
      [ definition, readOnly ],
      [ rule, readOnly ],
      [ subject, none ],
      [ resource, none ],
    ]);
    const credentialSets: Credentials[] = [{ agent: { webId: 'http://example.com/alice/profile/card#me' }}, {}];
    for (const credentials of credentialSets) {
      compareMaps(await reader.handle({ credentials, requestedModes: request(targets) }), expected);
    }
  });

  it('can guard a store in a different container.', async(): Promise<void> => {
    const reader = new AbacStoreReader(baseUrl, admin, 'attributes/');
    const moved = { path: `${baseUrl}attributes/rules/R001` };
    const result = await reader.handle({ credentials: {}, requestedModes: request([ rule, moved ]) });
    compareMaps(result, new IdentifierMap([[ rule, none ], [ moved, readOnly ]]));
  });
});

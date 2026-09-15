import { Parser, Store } from 'n3';
import type { Credentials } from '../../../../src/authentication/Credentials';
import type { AbacDataLoader } from '../../../../src/authorization/abac/AbacDataLoader';
import { AbacPermissionReader } from '../../../../src/authorization/abac/AbacPermissionReader';
import { AclMode } from '../../../../src/authorization/permissions/AclPermissionSet';
import type { AccessMap } from '../../../../src/authorization/permissions/Permissions';
import { AccessMode } from '../../../../src/authorization/permissions/Permissions';
import type { ResourceIdentifier } from '../../../../src/http/representation/ResourceIdentifier';
import { SingleRootIdentifierStrategy } from '../../../../src/util/identifiers/SingleRootIdentifierStrategy';
import { IdentifierMap, IdentifierSetMultiMap } from '../../../../src/util/map/IdentifierMap';
import { compareMaps } from '../../../util/Util';

describe('An AbacPermissionReader', (): void => {
  const baseUrl = 'http://example.com/';
  const alice = 'http://example.com/alice/profile/card#me';
  const bob = 'http://example.com/bob/profile/card#me';
  const target = { path: `${baseUrl}records/note.ttl` };
  const other = { path: `${baseUrl}records/other.ttl` };

  function parse(turtle: string): Store {
    return new Store(new Parser({ baseIRI: baseUrl }).parse(`
    @prefix abac: <https://w3id.org/solid-abac#>.
    @prefix acl: <http://www.w3.org/ns/auth/acl#>.
    @prefix ex: <http://example.org/hospital#>.
    ${turtle}`));
  }

  const definitions = parse(`
    ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:None .
    ex:category a abac:AttributeDefinition ; abac:appliesTo abac:Resource ; abac:defaultValue ex:Uncategorised .
  `);
  // Each also claims an attribute that describes the other kind of entity, which must be ignored.
  const subjects = parse(`<${alice}> ex:role ex:Doctor ; ex:category ex:Medical .`);
  const resources = parse(`
    <${baseUrl}records/> ex:category ex:Medical ; ex:role ex:Doctor .
    <${baseUrl}records/admin/> ex:category ex:Administrative .
  `);

  // `ex:Teleport` is not an ACL mode and must be ignored.
  const matching = parse(`
    <#R001> a abac:Rule ;
      abac:grants acl:Read, acl:Write, acl:Control, ex:Teleport ;
      abac:allOf [ ex:role ex:Doctor ] .
  `);
  const nonMatching = parse(`
    <#R002> a abac:Rule ; abac:grants acl:Read ; abac:allOf [ ex:role ex:Surgeon ] .
  `);
  const medical = parse(`
    <#R003> a abac:Rule ; abac:grants acl:Read ; abac:allOf [ ex:role ex:Doctor ], [ ex:category ex:Medical ] .
  `);

  let credentials: Credentials;
  let requestedModes: AccessMap;

  function createReader(rules: Store, excludePaths = [ '^$', '^/\\..*' ]): AbacPermissionReader {
    const loader = {
      readDefinitions: jest.fn().mockResolvedValue(definitions),
      readSubjectAttributes: jest.fn().mockResolvedValue(subjects),
      readResourceAttributes: jest.fn().mockResolvedValue(resources),
      readRules: jest.fn().mockResolvedValue(rules),
    } satisfies Partial<AbacDataLoader> as any;
    return new AbacPermissionReader(loader, new SingleRootIdentifierStrategy(baseUrl), baseUrl, excludePaths);
  }

  function readRequest(...paths: string[]): AccessMap {
    return new IdentifierSetMultiMap(paths.map((path): [ResourceIdentifier, AccessMode] =>
      [{ path: `${baseUrl}${path}` }, AccessMode.read ])) as any;
  }

  beforeEach((): void => {
    credentials = { agent: { webId: alice }};
    requestedModes = new IdentifierSetMultiMap([[ target, AccessMode.read ]]) as any;
  });

  it('grants the mapped modes of a matching rule on every requested target.', async(): Promise<void> => {
    requestedModes = new IdentifierSetMultiMap([
      [ target, AccessMode.read ],
      [ other, AccessMode.write ],
    ]) as any;
    const granted = {
      [AccessMode.read]: true,
      [AccessMode.append]: true,
      [AccessMode.write]: true,
      [AclMode.control]: true,
    };
    const result = await createReader(matching).handle({ credentials, requestedModes });
    compareMaps(result, new IdentifierMap([[ target, granted ], [ other, granted ]]));
  });

  it('decides each target by the attribute values it inherits from its closest ancestor.', async(): Promise<void> => {
    requestedModes = readRequest('records/', 'records/2026/note.ttl', 'records/admin/rota.txt', 'photos/img.jpg', '');
    const result = await createReader(medical).handle({ credentials, requestedModes });
    compareMaps(result, new IdentifierMap([
      [{ path: `${baseUrl}records/` }, { [AccessMode.read]: true }],
      [{ path: `${baseUrl}records/2026/note.ttl` }, { [AccessMode.read]: true }],
    ]));
  });

  it('resolves each attribute only against the kind of entity its definition applies to.', async(): Promise<void> => {
    const reader = createReader(medical);
    requestedModes = readRequest('photos/img.jpg');
    compareMaps(await reader.handle({ credentials, requestedModes }), new IdentifierMap());
    requestedModes = readRequest('records/2026/note.ttl');
    compareMaps(await reader.handle({ credentials: { agent: { webId: bob }}, requestedModes }), new IdentifierMap());
  });

  it('has no opinion when no rule matches the agent.', async(): Promise<void> => {
    const result = await createReader(nonMatching).handle({ credentials, requestedModes });
    compareMaps(result, new IdentifierMap());
  });

  it('has no opinion on a request it cannot identify an agent for.', async(): Promise<void> => {
    const result = await createReader(matching).handle({ credentials: {}, requestedModes });
    compareMaps(result, new IdentifierMap());
  });

  it('never grants anything on an excluded or off-server resource.', async(): Promise<void> => {
    const internal = { path: `${baseUrl}.internal/foo` };
    const root = { path: 'http://example.com' };
    const elsewhere = { path: 'http://elsewhere.example/other' };
    requestedModes = new IdentifierSetMultiMap(
      [ internal, root, elsewhere ].map((id): [any, any] => [ id, AccessMode.read ]),
    ) as any;
    const result = await createReader(matching).handle({ credentials, requestedModes });
    compareMaps(result, new IdentifierMap());
  });

  it('never returns false for any mode, on any input.', async(): Promise<void> => {
    const allModes = [ ...Object.values(AccessMode), ...Object.values(AclMode) ];
    const targets = [ target, { path: `${baseUrl}.internal/foo` }, { path: 'http://elsewhere.example/x' }];
    const credentialSets: Credentials[] = [
      { agent: { webId: alice }},
      { agent: { webId: `${baseUrl}nobody#me` }},
      {},
    ];

    for (const rules of [ matching, nonMatching, medical, new Store() ]) {
      for (const creds of credentialSets) {
        for (const id of targets) {
          const modes = new IdentifierSetMultiMap(allModes.map((mode): [any, any] => [ id, mode ])) as any;
          const result = await createReader(rules).handle({ credentials: creds, requestedModes: modes });
          for (const [ , permissionSet ] of result) {
            expect(Object.values(permissionSet)).not.toContain(false);
          }
        }
      }
    }
  });
});

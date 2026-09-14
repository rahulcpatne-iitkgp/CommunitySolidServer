import { Parser, Store } from 'n3';
import type { Credentials } from '../../../../src/authentication/Credentials';
import type { AbacDataLoader } from '../../../../src/authorization/abac/AbacDataLoader';
import { AbacPermissionReader } from '../../../../src/authorization/abac/AbacPermissionReader';
import { AclMode } from '../../../../src/authorization/permissions/AclPermissionSet';
import type { AccessMap } from '../../../../src/authorization/permissions/Permissions';
import { AccessMode } from '../../../../src/authorization/permissions/Permissions';
import { IdentifierMap, IdentifierSetMultiMap } from '../../../../src/util/map/IdentifierMap';
import { compareMaps } from '../../../util/Util';

describe('An AbacPermissionReader', (): void => {
  const baseUrl = 'http://example.com/';
  const alice = 'http://example.com/alice/profile/card#me';
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
  `);
  const assignments = parse(`<${alice}> ex:role ex:Doctor .`);

  // `ex:Teleport` is not an ACL mode and must be ignored.
  const matching = parse(`
    <#R001> a abac:Rule ;
      abac:grants acl:Read, acl:Write, acl:Control, ex:Teleport ;
      abac:allOf [ ex:role ex:Doctor ] .
  `);
  const nonMatching = parse(`
    <#R002> a abac:Rule ; abac:grants acl:Read ; abac:allOf [ ex:role ex:Surgeon ] .
  `);

  let credentials: Credentials;
  let requestedModes: AccessMap;

  function createReader(rules: Store, excludePaths = [ '^$', '^/\\..*' ]): AbacPermissionReader {
    const loader = {
      readDefinitions: jest.fn().mockResolvedValue(definitions),
      readSubjectAttributes: jest.fn().mockResolvedValue(assignments),
      readRules: jest.fn().mockResolvedValue(rules),
    } satisfies Partial<AbacDataLoader> as any;
    return new AbacPermissionReader(loader, baseUrl, excludePaths);
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

    for (const rules of [ matching, nonMatching, new Store() ]) {
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

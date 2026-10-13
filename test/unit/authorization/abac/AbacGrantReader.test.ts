import { Parser, Store } from 'n3';
import type { Credentials } from '../../../../src/authentication/Credentials';
import type { AbacDataLoader } from '../../../../src/authorization/abac/AbacDataLoader';
import { AbacGrantReader } from '../../../../src/authorization/abac/AbacGrantReader';
import { EnvironmentAttributeResolver } from '../../../../src/authorization/abac/EnvironmentAttributeResolver';
import type { AccessMap } from '../../../../src/authorization/permissions/Permissions';
import { AccessMode } from '../../../../src/authorization/permissions/Permissions';
import type { ResourceIdentifier } from '../../../../src/http/representation/ResourceIdentifier';
import type { Logger } from '../../../../src/logging/Logger';
import { getLoggerFor } from '../../../../src/logging/LogUtil';
import type { IdentifierStrategy } from '../../../../src/util/identifiers/IdentifierStrategy';
import { SingleRootIdentifierStrategy } from '../../../../src/util/identifiers/SingleRootIdentifierStrategy';
import { SubdomainIdentifierStrategy } from '../../../../src/util/identifiers/SubdomainIdentifierStrategy';
import { IdentifierSetMultiMap } from '../../../../src/util/map/IdentifierMap';
import { ACL } from '../../../../src/util/Vocabularies';
import { compareMaps } from '../../../util/Util';

jest.mock('../../../../src/logging/LogUtil', (): any => {
  const logger: Logger = { debug: jest.fn(), warn: jest.fn() } as any;
  return { getLoggerFor: (): Logger => logger };
});

describe('An AbacGrantReader', (): void => {
  const logger: jest.Mocked<Logger> = getLoggerFor('AbacGrantReader') as any;
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

  const role = `ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ;
    abac:value ex:None, ex:Doctor, ex:Surgeon ; abac:defaultValue ex:None .`;
  const definitions = parse(`${role}
    ex:category a abac:AttributeDefinition ; abac:appliesTo abac:Resource ;
      abac:value ex:Uncategorised, ex:Medical, ex:Administrative ; abac:defaultValue ex:Uncategorised .
  `);
  const withPeriod = parse(`${role}
    abac:period a abac:AttributeDefinition ; abac:appliesTo abac:Environment ;
      abac:value abac:BusinessHours, abac:OutOfHours ; abac:defaultValue abac:OutOfHours .
  `);
  // Each also claims an attribute that describes the other kind of entity, which must be ignored.
  const subjects = parse(`<${alice}> ex:role ex:Doctor ; ex:category ex:Medical .`);
  const resources = parse(`
    <${baseUrl}records/> ex:category ex:Medical ; ex:role ex:Doctor .
    <${baseUrl}records/admin/> ex:category ex:Administrative .
  `);

  const matching = parse(`
    <#R001> a abac:Rule ; abac:grants acl:Read, acl:Write, acl:Control ; abac:allOf [ ex:role ex:Doctor ] .
  `);
  const nonMatching = parse(`
    <#R002> a abac:Rule ; abac:grants acl:Read ; abac:allOf [ ex:role ex:Surgeon ] .
  `);
  const medical = parse(`
    <#R003> a abac:Rule ; abac:grants acl:Read ; abac:allOf [ ex:role ex:Doctor ], [ ex:category ex:Medical ] .
  `);
  const duringHours = parse(`
    <#R004> a abac:Rule ; abac:grants acl:Read ;
      abac:allOf [ ex:role ex:Doctor ], [ abac:period abac:BusinessHours ] .
  `);
  const malformed = parse(`
    <#R005> a abac:Rule ; abac:grants acl:Write ;
      abac:allOf [ ex:role ex:Doctor ] ; abac:noneOf [ ex:status ex:Suspended ] .
    <#R006> a abac:Rule ; abac:grants acl:Write ;
      abac:allOf [ ex:role ex:Doctor ] ; abac:noneOf [ ex:category ex:Medical, ex:Psychiatric ] .
  `);

  const noGrants = new IdentifierSetMultiMap<string>();
  const businessHours = new Date('2026-10-07T10:00:00');
  const outOfHours = new Date('2026-10-07T22:00:00');

  let credentials: Credentials;
  let requestedModes: AccessMap;

  function createReader(
    rules: Store,
    definitionData = definitions,
    identifierStrategy: IdentifierStrategy = new SingleRootIdentifierStrategy(baseUrl),
  ): AbacGrantReader {
    const loader = {
      readDefinitions: jest.fn().mockResolvedValue(definitionData),
      readSubjectAttributes: jest.fn().mockResolvedValue(subjects),
      readResourceAttributes: jest.fn().mockResolvedValue(resources),
      readRules: jest.fn().mockResolvedValue(rules),
    } satisfies Partial<AbacDataLoader> as any;
    const resolver = new EnvironmentAttributeResolver('09:00', '17:00', [ '^127\\.' ]);
    return new AbacGrantReader(loader, identifierStrategy, resolver, baseUrl, [ '^/\\..*' ]);
  }

  function readRequest(...paths: string[]): AccessMap {
    return new IdentifierSetMultiMap(paths.map((path): [ResourceIdentifier, AccessMode] =>
      [{ path: `${baseUrl}${path}` }, AccessMode.read ])) as any;
  }

  beforeEach((): void => {
    jest.clearAllMocks();
    credentials = { agent: { webId: alice }};
    requestedModes = new IdentifierSetMultiMap([[ target, AccessMode.read ]]) as any;
  });

  it('grants the modes of a matching rule on every requested target.', async(): Promise<void> => {
    requestedModes = new IdentifierSetMultiMap([
      [ target, AccessMode.read ],
      [ other, AccessMode.write ],
    ]) as any;
    const granted = new Set([ ACL.Read, ACL.Write, ACL.Control ]);
    const result = await createReader(matching).handle({ credentials, requestedModes });
    compareMaps(result, new IdentifierSetMultiMap([[ target, granted ], [ other, granted ]]));
  });

  it('decides each target by the attribute values it inherits from its closest ancestor.', async(): Promise<void> => {
    requestedModes = readRequest('records/', 'records/2026/note.ttl', 'records/admin/rota.txt', 'photos/img.jpg', '');
    const result = await createReader(medical).handle({ credentials, requestedModes });
    compareMaps(result, new IdentifierSetMultiMap([
      [{ path: `${baseUrl}records/` }, ACL.Read ],
      [{ path: `${baseUrl}records/2026/note.ttl` }, ACL.Read ],
    ]));
  });

  it('resolves each attribute only against the kind of entity its definition applies to.', async(): Promise<void> => {
    const reader = createReader(medical);
    requestedModes = readRequest('photos/img.jpg');
    compareMaps(await reader.handle({ credentials, requestedModes }), noGrants);
    requestedModes = readRequest('records/2026/note.ttl');
    compareMaps(await reader.handle({ credentials: { agent: { webId: bob }}, requestedModes }), noGrants);
  });

  it('decides by the circumstances the request was made in.', async(): Promise<void> => {
    const reader = createReader(duringHours, withPeriod);
    credentials = { agent: { webId: alice }, environment: { timestamp: businessHours }};
    compareMaps(
      await reader.handle({ credentials, requestedModes }),
      new IdentifierSetMultiMap([[ target, ACL.Read ]]),
    );
    credentials = { agent: { webId: alice }, environment: { timestamp: outOfHours }};
    compareMaps(await reader.handle({ credentials, requestedModes }), noGrants);
  });

  it('falls back to the declared default without a valid record of the circumstances.', async(): Promise<void> => {
    const reader = createReader(duringHours, withPeriod);
    compareMaps(await reader.handle({ credentials, requestedModes }), noGrants);
    credentials = { agent: { webId: alice }, environment: { timestamp: businessHours.toISOString() }};
    compareMaps(await reader.handle({ credentials, requestedModes }), noGrants);
    expect(logger.warn).toHaveBeenCalledTimes(2);
  });

  it('warns about a rule naming an undefined attribute or value, which grants nothing.', async(): Promise<void> => {
    const result = await createReader(malformed).handle({ credentials, requestedModes });
    compareMaps(result, noGrants);
    expect(logger.warn).toHaveBeenCalledWith(
      `Rule ${baseUrl}#R005 never matches, as it names undefined attributes: http://example.org/hospital#status`,
    );
    expect(logger.warn).toHaveBeenCalledWith(`Rule ${baseUrl}#R006 never matches, as it names values ` +
      `outside their attributes' value spaces: http://example.org/hospital#Psychiatric`);
  });

  it('has no opinion when no rule matches the agent.', async(): Promise<void> => {
    const result = await createReader(nonMatching).handle({ credentials, requestedModes });
    compareMaps(result, noGrants);
  });

  it('has no opinion on a request it cannot identify an agent for.', async(): Promise<void> => {
    const result = await createReader(matching).handle({ credentials: {}, requestedModes });
    compareMaps(result, noGrants);
  });

  it('never grants anything on an excluded or off-server resource.', async(): Promise<void> => {
    const internal = { path: `${baseUrl}.internal/foo` };
    const root = { path: 'http://example.com' };
    const elsewhere = { path: 'http://elsewhere.example/other' };
    requestedModes = new IdentifierSetMultiMap(
      [ internal, root, elsewhere ].map((id): [any, any] => [ id, AccessMode.read ]),
    ) as any;
    const result = await createReader(matching).handle({ credentials, requestedModes });
    compareMaps(result, noGrants);
  });

  it('grants on a pod on a subdomain, but not on the server namespaces.', async(): Promise<void> => {
    const pod = { path: 'http://alice.example.com/records/note.ttl' };
    const internal = { path: `${baseUrl}.internal/foo` };
    requestedModes = new IdentifierSetMultiMap([[ pod, AccessMode.read ], [ internal, AccessMode.read ]]) as any;
    const reader = createReader(matching, definitions, new SubdomainIdentifierStrategy(baseUrl));
    compareMaps(
      await reader.handle({ credentials, requestedModes }),
      new IdentifierSetMultiMap([[ pod, new Set([ ACL.Read, ACL.Write, ACL.Control ]) ]]),
    );
  });
});

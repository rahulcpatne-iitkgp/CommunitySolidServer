import { Parser, Store } from 'n3';
import type { Credentials } from '../../../../src/authentication/Credentials';
import type { AbacDataLoader } from '../../../../src/authorization/abac/AbacDataLoader';
import { AbacAllowedModesReader } from '../../../../src/authorization/abac/AbacAllowedModesReader';
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

describe('An AbacAllowedModesReader', (): void => {
  const logger: jest.Mocked<Logger> = getLoggerFor('AbacAllowedModesReader') as any;
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

  const roleAndFileType = `
    ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ;
      abac:value ex:None, ex:Doctor, ex:Surgeon ; abac:defaultValue ex:None .
    ex:fileType a abac:AttributeDefinition ; abac:appliesTo abac:Resource ;
      abac:value ex:Unspecified, ex:Medical, ex:Administrative ; abac:defaultValue ex:Unspecified .`;
  const definitions = parse(roleAndFileType);
  const withPeriod = parse(`${roleAndFileType}
    abac:period a abac:AttributeDefinition ; abac:appliesTo abac:Environment ;
      abac:value abac:BusinessHours, abac:OutOfHours ; abac:defaultValue abac:OutOfHours .
  `);
  // Each also claims an attribute that describes the other kind of entity, which must be ignored.
  const subjects = parse(`<${alice}> ex:role ex:Doctor ; ex:fileType ex:Medical .`);
  const resources = parse(`
    <${baseUrl}records/> ex:fileType ex:Medical ; ex:role ex:Doctor .
    <${baseUrl}records/admin/> ex:fileType ex:Administrative .
  `);

  // Matches medical and unlabelled resources alike, so only the exclusions keep it from the server's own.
  const matching = parse(`
    <#R001> a abac:Rule ; abac:allow acl:Read, acl:Write, acl:Control ;
      abac:allOf [ ex:role ex:Doctor ] ; abac:anyOf [ ex:fileType ex:Medical ], [ ex:fileType ex:Unspecified ] .
  `);
  const nonMatching = parse(`
    <#R002> a abac:Rule ; abac:allow acl:Read ; abac:allOf [ ex:role ex:Surgeon ], [ ex:fileType ex:Medical ] .
  `);
  const medical = parse(`
    <#R003> a abac:Rule ; abac:allow acl:Read ; abac:allOf [ ex:role ex:Doctor ], [ ex:fileType ex:Medical ] .
  `);
  const duringHours = parse(`
    <#R004> a abac:Rule ; abac:allow acl:Read ;
      abac:allOf [ ex:role ex:Doctor ], [ ex:fileType ex:Medical ], [ abac:period abac:BusinessHours ] .
  `);
  const unmatchable = parse(`
    <#R005> a abac:Rule ; abac:allow acl:Write ;
      abac:allOf [ ex:role ex:Doctor ], [ ex:fileType ex:Medical ] ; abac:noneOf [ ex:status ex:Suspended ] .
    <#R006> a abac:Rule ; abac:allow acl:Write ;
      abac:allOf [ ex:role ex:Doctor ], [ ex:fileType ex:Medical ] ; abac:noneOf [ ex:fileType ex:Psychiatric ] .
    <#R007> a abac:Rule ; abac:allow acl:Write ; abac:allOf [ ex:role ex:Doctor ] .
    <#R008> a abac:Rule ; abac:allow acl:Write ;
      abac:allOf [ ex:role ex:Doctor ] ; abac:noneOf [ ex:fileType ex:Administrative ] .
    <#R009> a abac:Rule ; abac:allow acl:Write ; abac:anyOf [ ex:role ex:Doctor ], [ ex:fileType ex:Medical ] .
  `);

  const noAllowedModes = new IdentifierSetMultiMap<string>();
  const businessHours = new Date('2026-10-07T10:00:00');
  const outOfHours = new Date('2026-10-07T22:00:00');

  let credentials: Credentials;
  let requestedModes: AccessMap;

  function createReader(
    rules: Store | Error,
    definitionData = definitions,
    identifierStrategy: IdentifierStrategy = new SingleRootIdentifierStrategy(baseUrl),
  ): AbacAllowedModesReader {
    const loader = {
      readDefinitions: jest.fn().mockResolvedValue(definitionData),
      readSubjectAttributes: jest.fn().mockResolvedValue(subjects),
      readResourceAttributes: jest.fn().mockResolvedValue(resources),
      readRules: jest.fn().mockImplementation(async(): Promise<Store> => {
        if (rules instanceof Error) {
          throw rules;
        }
        return rules;
      }),
    } satisfies Partial<AbacDataLoader> as any;
    const resolver = new EnvironmentAttributeResolver('09:00', '17:00', [ '^127\\.' ]);
    return new AbacAllowedModesReader(loader, identifierStrategy, resolver, baseUrl, [ '^/\\..*' ]);
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

  it('allows the modes of a matching rule on every requested target.', async(): Promise<void> => {
    requestedModes = new IdentifierSetMultiMap([
      [ target, AccessMode.read ],
      [ other, AccessMode.write ],
    ]) as any;
    const allowed = new Set([ ACL.Read, ACL.Write, ACL.Control ]);
    const result = await createReader(matching).handle({ credentials, requestedModes });
    compareMaps(result, new IdentifierSetMultiMap([[ target, allowed ], [ other, allowed ]]));
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
    compareMaps(await reader.handle({ credentials, requestedModes }), noAllowedModes);
    requestedModes = readRequest('records/2026/note.ttl');
    compareMaps(await reader.handle({ credentials: { agent: { webId: bob }}, requestedModes }), noAllowedModes);
  });

  it('decides by the circumstances the request was made in.', async(): Promise<void> => {
    const reader = createReader(duringHours, withPeriod);
    credentials = { agent: { webId: alice }, environment: { timestamp: businessHours }};
    compareMaps(
      await reader.handle({ credentials, requestedModes }),
      new IdentifierSetMultiMap([[ target, ACL.Read ]]),
    );
    credentials = { agent: { webId: alice }, environment: { timestamp: outOfHours }};
    compareMaps(await reader.handle({ credentials, requestedModes }), noAllowedModes);
  });

  it('falls back to the declared default without a valid record of the circumstances.', async(): Promise<void> => {
    const reader = createReader(duringHours, withPeriod);
    compareMaps(await reader.handle({ credentials, requestedModes }), noAllowedModes);
    credentials = { agent: { webId: alice }, environment: { timestamp: businessHours.toISOString() }};
    compareMaps(await reader.handle({ credentials, requestedModes }), noAllowedModes);
    expect(logger.warn).toHaveBeenCalledTimes(2);
  });

  it('warns about every rule that can never match, and allows nothing by it.', async(): Promise<void> => {
    const result = await createReader(unmatchable).handle({ credentials, requestedModes });
    compareMaps(result, noAllowedModes);
    expect(logger.warn.mock.calls).toEqual([
      [ `Rule ${baseUrl}#R005 never matches, as it names undefined attributes: http://example.org/hospital#status` ],
      [ `Rule ${baseUrl}#R006 never matches, as it names values outside their attributes' value spaces: ` +
        `http://example.org/hospital#Psychiatric` ],
      ...[ 'R007', 'R008', 'R009' ].map((rule): string[] => [ `Rule ${baseUrl}#${rule} never matches, as it ` +
        `does not condition on the resource, through allOf or an anyOf naming only resource attributes` ]),
    ]);
  });

  it('has no opinion when no rule matches the agent.', async(): Promise<void> => {
    const result = await createReader(nonMatching).handle({ credentials, requestedModes });
    compareMaps(result, noAllowedModes);
  });

  it('has no opinion on a request it cannot identify an agent for.', async(): Promise<void> => {
    const result = await createReader(matching).handle({ credentials: {}, requestedModes });
    compareMaps(result, noAllowedModes);
  });

  it('still prepares resource attributes for an anonymous owner matcher, ' +
    'without catalogue allowed modes.', async(): Promise<void> => {
    const { context, allowedModes } = await createReader(matching).prepare({ credentials: {}, requestedModes });
    expect(context.vectors.get(target)).toEqual({ 'http://example.org/hospital#fileType':
      'http://example.org/hospital#Medical' });
    compareMaps(allowedModes, noAllowedModes);
  });

  it('keeps the attribute context when the catalogue is unreadable.', async(): Promise<void> => {
    const { context, allowedModes } = await createReader(new Error('unavailable'))
      .prepare({ credentials, requestedModes });
    expect(context.vectors.get(target)?.['http://example.org/hospital#role'])
      .toBe('http://example.org/hospital#Doctor');
    compareMaps(allowedModes, noAllowedModes);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('unavailable'));
  });

  it('never allows anything on an excluded or off-server resource.', async(): Promise<void> => {
    const internal = { path: `${baseUrl}.internal/foo` };
    const root = { path: 'http://example.com' };
    const elsewhere = { path: 'http://elsewhere.example/other' };
    requestedModes = new IdentifierSetMultiMap(
      [ internal, root, elsewhere ].map((id): [any, any] => [ id, AccessMode.read ]),
    ) as any;
    const result = await createReader(matching).handle({ credentials, requestedModes });
    compareMaps(result, noAllowedModes);
  });

  it('allows on a pod on a subdomain, but not on the server namespaces.', async(): Promise<void> => {
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

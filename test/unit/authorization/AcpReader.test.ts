import { Parser } from 'n3';
import type { Quad } from '@rdfjs/types';
import type { Credentials } from '../../../src/authentication/Credentials';
import { AcpReader } from '../../../src/authorization/AcpReader';
import type { AbacAllowedModesReader } from '../../../src/authorization/abac/AbacAllowedModesReader';
import type { AllowedModesReader } from '../../../src/authorization/AllowedModesReader';
import { AccessMode } from '../../../src/authorization/permissions/Permissions';
import type { AuxiliaryStrategy } from '../../../src/http/auxiliary/AuxiliaryStrategy';
import { BasicRepresentation } from '../../../src/http/representation/BasicRepresentation';
import type { Representation } from '../../../src/http/representation/Representation';
import type { ResourceStore } from '../../../src/storage/ResourceStore';
import { INTERNAL_QUADS } from '../../../src/util/ContentTypes';
import { NotFoundHttpError } from '../../../src/util/errors/NotFoundHttpError';
import type { IdentifierStrategy } from '../../../src/util/identifiers/IdentifierStrategy';
import { SingleRootIdentifierStrategy } from '../../../src/util/identifiers/SingleRootIdentifierStrategy';
import { IdentifierMap, IdentifierSetMultiMap } from '../../../src/util/map/IdentifierMap';
import { joinUrl } from '../../../src/util/PathUtil';
import { ACL } from '../../../src/util/Vocabularies';
import { SimpleSuffixStrategy } from '../../util/SimpleSuffixStrategy';
import { compareMaps } from '../../util/Util';

const acrSuffix = '.acr';

function toQuads(turtle: string, baseIRI: string): Quad[] {
  baseIRI = `${baseIRI}${acrSuffix}`;
  turtle = `
  @prefix acp: <http://www.w3.org/ns/solid/acp#>.
  @prefix acl: <http://www.w3.org/ns/auth/acl#>.
  ${turtle}
  `;
  return new Parser({ format: 'Turtle', baseIRI }).parse(turtle);
}

describe('An AcpReader', (): void => {
  const baseUrl = 'http://example.com/';
  let credentials: Credentials;
  // Subject identifiers are used as keys, values are the output of their corresponding ACR resource
  let dataMap: Record<string, Quad[]>;
  let acrStrategy: AuxiliaryStrategy;
  let acrStore: jest.Mocked<ResourceStore>;
  let identifierStrategy: IdentifierStrategy;
  let acpReader: AcpReader;

  beforeEach(async(): Promise<void> => {
    credentials = {};
    dataMap = {};

    acrStrategy = new SimpleSuffixStrategy(acrSuffix);

    acrStore = {
      getRepresentation: jest.fn((identifier): Representation => {
        const subjectIdentifier = acrStrategy.getSubjectIdentifier(identifier);
        if (!dataMap[subjectIdentifier.path]) {
          throw new NotFoundHttpError();
        }
        return new BasicRepresentation(dataMap[subjectIdentifier.path], subjectIdentifier, INTERNAL_QUADS, false);
      }),
    } as any;

    identifierStrategy = new SingleRootIdentifierStrategy(baseUrl);

    acpReader = new AcpReader(acrStrategy, acrStore, identifierStrategy);
  });

  it('can check permissions on the root container.', async(): Promise<void> => {
    const target = { path: joinUrl(baseUrl, 'foo') };
    dataMap[baseUrl] = toQuads(`
      []
        acp:resource <./>;
        acp:accessControl [ acp:apply _:policy ].
      _:policy
        acp:allow acl:Read;
        acp:allOf _:matcher.
      _:matcher acp:agent acp:PublicAgent.
    `, baseUrl);
    const requestedModes = new IdentifierSetMultiMap([
      [{ path: baseUrl }, AccessMode.read ],
      [ target, AccessMode.read ],
    ]);
    const expectedPermissions = new IdentifierMap([
      [{ path: baseUrl }, { read: true }],
      [ target, {}],
    ]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expectedPermissions);
  });

  it('throws an error if something goes wrong reading data.', async(): Promise<void> => {
    acrStore.getRepresentation.mockRejectedValueOnce(new Error('bad request'));
    const requestedModes = new IdentifierSetMultiMap([[{ path: baseUrl }, AccessMode.read ]]);
    await expect(acpReader.handle({ credentials, requestedModes })).rejects.toThrow('bad request');
  });

  it('allows for permission inheritance.', async(): Promise<void> => {
    const target = { path: joinUrl(baseUrl, 'foo') };
    dataMap[baseUrl] = toQuads(`
      []
        acp:resource <./>;
        acp:memberAccessControl [ acp:apply _:policy ].
      _:policy
        acp:allow acl:Read;
        acp:allOf _:matcher.
      _:matcher acp:agent acp:PublicAgent.
    `, baseUrl);
    const requestedModes = new IdentifierSetMultiMap([
      [{ path: baseUrl }, AccessMode.read ],
      [ target, AccessMode.read ],
    ]);
    const expectedPermissions = new IdentifierMap([
      [{ path: baseUrl }, {}],
      [ target, { read: true }],
    ]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expectedPermissions);
  });

  it('combines all relevant ACRs.', async(): Promise<void> => {
    const target = { path: joinUrl(baseUrl, 'foo') };
    dataMap[baseUrl] = toQuads(`
      []
        acp:resource <./>;
        acp:accessControl [ acp:apply _:controlPolicy ];
        acp:memberAccessControl [ acp:apply _:readPolicy ].
      _:readPolicy
        acp:allow acl:Read;
        acp:allOf _:matcher.
      _:controlPolicy
        acp:allow acl:Control;
        acp:allOf _:matcher.
      _:matcher acp:agent acp:PublicAgent.
    `, baseUrl);
    dataMap[target.path] = toQuads(`
      []
        acp:resource <./foo>;
        acp:accessControl [ acp:apply _:appendPolicy ].
      _:appendPolicy
        acp:allow acl:Append;
        acp:allOf _:matcher.
      _:matcher acp:agent acp:PublicAgent.
    `, target.path);
    const requestedModes = new IdentifierSetMultiMap([
      [{ path: baseUrl }, AccessMode.read ],
      [ target, AccessMode.read ],
    ]);
    const expectedPermissions = new IdentifierMap([
      [{ path: baseUrl }, { control: true }],
      [ target, { read: true, append: true }],
    ]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expectedPermissions);
  });

  it('caches data to prevent duplicate ResourceStore calls.', async(): Promise<void> => {
    const target1 = { path: joinUrl(baseUrl, 'foo/') };
    const target2 = { path: joinUrl(baseUrl, 'foo/bar') };
    dataMap[baseUrl] = toQuads(`
      []
        acp:resource <./>;
        acp:memberAccessControl [ acp:apply _:policy ].
      _:policy
        acp:allow acl:Read;
        acp:allOf _:matcher.
      _:matcher acp:agent acp:PublicAgent.
    `, baseUrl);
    const requestedModes = new IdentifierSetMultiMap([
      [{ path: baseUrl }, AccessMode.read ],
      [ target1, AccessMode.read ],
      [ target2, AccessMode.read ],
    ]);
    const expectedPermissions = new IdentifierMap([
      [{ path: baseUrl }, {}],
      [ target1, { read: true }],
      [ target2, { read: true }],
    ]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expectedPermissions);
    expect(acrStore.getRepresentation).toHaveBeenCalledTimes(3);
    expect(acrStore.getRepresentation)
      .toHaveBeenCalledWith(acrStrategy.getAuxiliaryIdentifier(target1), { type: { [INTERNAL_QUADS]: 1 }});
    expect(acrStore.getRepresentation)
      .toHaveBeenCalledWith(acrStrategy.getAuxiliaryIdentifier(target2), { type: { [INTERNAL_QUADS]: 1 }});
    expect(acrStore.getRepresentation)
      .toHaveBeenCalledWith(acrStrategy.getAuxiliaryIdentifier({ path: baseUrl }), { type: { [INTERNAL_QUADS]: 1 }});
  });

  it('correctly puts the credentials in the context.', async(): Promise<void> => {
    dataMap[baseUrl] = toQuads(`
      []
        acp:resource <./> ;
        acp:accessControl [ acp:apply _:policy ].
      _:policy
        acp:allow acl:Read;
        acp:allOf _:matcher.
      _:matcher 
        acp:agent <http://example.com/#me>;
        acp:client <http://client.example.com/#me>;
        acp:issuer <http://example.com/idp>.        
    `, baseUrl);
    const requestedModes = new IdentifierSetMultiMap([[{ path: baseUrl }, AccessMode.read ]]);
    let expectedPermissions = new IdentifierMap([[{ path: baseUrl }, {}]]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expectedPermissions);

    credentials = {
      agent: { webId: 'http://example.com/#me' },
      client: { clientId: 'http://client.example.com/#me' },
      issuer: { url: 'http://example.com/idp' },
    };
    expectedPermissions = new IdentifierMap([[{ path: baseUrl }, { read: true }]]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expectedPermissions);
  });

  it('adds outside allowed modes, other than Control, unless an applying policy denies them.', async(): Promise<void> => {
    const alice = 'http://example.com/alice#me';
    const target = { path: joinUrl(baseUrl, 'foo') };
    credentials = { agent: { webId: alice }};
    dataMap[baseUrl] = toQuads(`
      []
        acp:resource <./>;
        acp:memberAccessControl [ acp:apply _:aliceDenied, _:bobDenied ].
      _:aliceDenied
        acp:deny acl:Read, acl:Append;
        acp:allOf [ acp:agent <${alice}> ].
      _:bobDenied
        acp:deny acl:Write;
        acp:allOf [ acp:agent <http://example.com/bob#me> ].
    `, baseUrl);
    const allowedModesReader: jest.Mocked<AllowedModesReader> = {
      handleSafe: jest.fn().mockResolvedValue(new IdentifierSetMultiMap([
        [{ path: baseUrl }, new Set([ ACL.Read, 'http://example.com/#Teleport', 'constructor' ]) ],
        [ target, new Set([ ACL.Read, ACL.Write, ACL.Control ]) ],
      ])),
    } as any;
    acpReader = new AcpReader(acrStrategy, acrStore, identifierStrategy, allowedModesReader);
    const requestedModes = new IdentifierSetMultiMap([
      [{ path: baseUrl }, AccessMode.read ],
      [ target, AccessMode.read ],
    ]);
    const expectedPermissions = new IdentifierMap([
      [{ path: baseUrl }, { read: true }],
      [ target, { append: true, write: true }],
    ]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expectedPermissions);
    expect(allowedModesReader.handleSafe).toHaveBeenLastCalledWith({ credentials, requestedModes });
  });

  it('ignores outside allowed modes it cannot determine, but not ACRs it cannot read.', async(): Promise<void> => {
    dataMap[baseUrl] = toQuads(`
      []
        acp:resource <./>;
        acp:accessControl [ acp:apply _:policy ].
      _:policy
        acp:allow acl:Read;
        acp:allOf _:matcher.
      _:matcher acp:agent acp:PublicAgent.
    `, baseUrl);
    const allowedModesReader: jest.Mocked<AllowedModesReader> = {
      handleSafe: jest.fn().mockRejectedValue(new Error('unreachable')),
    } as any;
    acpReader = new AcpReader(acrStrategy, acrStore, identifierStrategy, allowedModesReader);
    const requestedModes = new IdentifierSetMultiMap([[{ path: baseUrl }, AccessMode.read ]]);
    const expectedPermissions = new IdentifierMap([[{ path: baseUrl }, { read: true }]]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expectedPermissions);

    allowedModesReader.handleSafe.mockResolvedValueOnce(
      new IdentifierSetMultiMap<string>([[{ path: baseUrl }, ACL.Write ]]),
    );
    acrStore.getRepresentation.mockRejectedValueOnce(new Error('bad request'));
    await expect(acpReader.handle({ credentials, requestedModes })).rejects.toThrow('bad request');
  });

  it('shares one attribute context across owner policies and catalogue rules.', async(): Promise<void> => {
    const role = 'http://example.org/role';
    const doctor = 'http://example.org/Doctor';
    const target = { path: joinUrl(baseUrl, 'record') };
    credentials = { agent: { webId: 'http://example.org/alice#me' }};
    dataMap[target.path] = toQuads(`
      [] acp:resource <./record>; acp:accessControl [ acp:apply [
        acp:allow acl:Write; acp:deny acl:Read;
        acp:allOf [ <${role}> <${doctor}> ]
      ]] .
    `, target.path);
    const requestedModes = new IdentifierSetMultiMap([[ target, AccessMode.read ]]);
    const vector = new IdentifierMap([[ target, { [role]: doctor }]]);
    const abacAllowedModesReader = { prepare: jest.fn().mockResolvedValue({
      context: { definitions: new Map([[ role, {
        iri: role,
        appliesTo: 'Subject',
        values: new Set([ doctor ]),
        defaultValue: doctor,
      }]]), vectors: vector },
      allowedModes: new IdentifierSetMultiMap([[ target, ACL.Read ]]),
    }) } as unknown as AbacAllowedModesReader;
    acpReader = new AcpReader(acrStrategy, acrStore, identifierStrategy, undefined, abacAllowedModesReader);
    const expected = new IdentifierMap([[ target, { append: true, write: true }]]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expected);
    expect(abacAllowedModesReader.prepare).toHaveBeenCalledTimes(1);
  });

  it('reports an attribute-store outage for owner attribute policies, ' +
    'but preserves identity-only ACP.', async(): Promise<void> => {
    const target = { path: joinUrl(baseUrl, 'record') };
    const requestedModes = new IdentifierSetMultiMap([[ target, AccessMode.read ]]);
    const abacAllowedModesReader = {
      prepare: jest.fn().mockRejectedValue(new Error('store unavailable')),
    } as unknown as AbacAllowedModesReader;
    acpReader = new AcpReader(acrStrategy, acrStore, identifierStrategy, undefined, abacAllowedModesReader);
    dataMap[target.path] = toQuads(`
        [] acp:resource <./record>; acp:accessControl [ acp:apply [
          acp:allow acl:Read; acp:allOf [ <http://example.org/role> <http://example.org/Doctor> ]
        ]] .
      `, target.path);
    await expect(acpReader.handle({ credentials, requestedModes }))
      .rejects.toThrow('Cannot evaluate owner attribute policies: store unavailable');

    dataMap[target.path] = toQuads(`
        [] acp:resource <./record>; acp:accessControl [ acp:apply [
          acp:allow acl:Read; acp:allOf [ acp:agent acp:PublicAgent ]
        ]] .
      `, target.path);
    const expected = new IdentifierMap([[ target, { read: true }]]);
    compareMaps(await acpReader.handle({ credentials, requestedModes }), expected);
  });
});

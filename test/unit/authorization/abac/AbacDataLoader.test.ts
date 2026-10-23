import { Parser } from 'n3';
import type { Quad } from '@rdfjs/types';
import { RepresentationMetadata } from '../../../../src/http/representation/RepresentationMetadata';
import { AbacDataLoader } from '../../../../src/authorization/abac/AbacDataLoader';
import type { Representation } from '../../../../src/http/representation/Representation';
import type { ResourceIdentifier } from '../../../../src/http/representation/ResourceIdentifier';
import type { ResourceStore } from '../../../../src/storage/ResourceStore';
import { InternalServerError } from '../../../../src/util/errors/InternalServerError';
import { NotFoundHttpError } from '../../../../src/util/errors/NotFoundHttpError';
import type { Logger } from '../../../../src/logging/Logger';
import { getLoggerFor } from '../../../../src/logging/LogUtil';
import { guardedStreamFrom } from '../../../../src/util/StreamUtil';
import { LDP } from '../../../../src/util/Vocabularies';

jest.mock('../../../../src/logging/LogUtil', (): any => {
  const logger: Logger = { debug: jest.fn(), warn: jest.fn(), error: jest.fn() } as any;
  return { getLoggerFor: (): Logger => logger };
});

const baseUrl = 'http://example.com/';

const prefixes = `
@prefix abac: <https://w3id.org/solid-abac#>.
@prefix ex:   <http://example.org/hospital#>.
`;

function parse(turtle: string): Quad[] {
  return new Parser({ baseIRI: baseUrl }).parse(prefixes + turtle);
}

/**
 * A container representation listing the given children through `ldp:contains`.
 * A trailing slash on a child makes it a nested container.
 */
function container(path: string, children: string[]): Representation {
  const metadata = new RepresentationMetadata({ path });
  for (const child of children) {
    metadata.add(LDP.terms.contains, { value: child, termType: 'NamedNode' } as any);
  }
  return { metadata, data: guardedStreamFrom([]) } as any;
}

/**
 * A document representation streaming the given quads.
 */
function document(path: string, quads: Quad[]): Representation {
  return { metadata: new RepresentationMetadata({ path }), data: guardedStreamFrom(quads) } as any;
}

describe('An AbacDataLoader', (): void => {
  const logger: jest.Mocked<Logger> = getLoggerFor('AbacDataLoader') as any;
  const definitions = `${baseUrl}.abac/definitions/`;
  const subjects = `${baseUrl}.abac/subjects/`;
  const resourceAttributes = `${baseUrl}.abac/resources/`;
  const rules = `${baseUrl}.abac/rules/`;

  let resources: Record<string, Representation | Error>;
  let store: jest.Mocked<ResourceStore>;
  let loader: AbacDataLoader;

  beforeEach((): void => {
    jest.clearAllMocks();
    resources = {};
    store = {
      getRepresentation: jest.fn(async(identifier: ResourceIdentifier): Promise<Representation> => {
        const result = resources[identifier.path] ?? new NotFoundHttpError();
        if (result instanceof Error) {
          throw result;
        }
        return result;
      }),
    } satisfies Partial<ResourceStore> as any;
    loader = new AbacDataLoader(store, baseUrl);
  });

  it('merges the quads of every document in a container.', async(): Promise<void> => {
    resources[definitions] = container(definitions, [ `${definitions}role`, `${definitions}department` ]);
    resources[`${definitions}role`] = document(`${definitions}role`, parse(
      `ex:role a abac:AttributeDefinition ; abac:defaultValue ex:None .`,
    ));
    resources[`${definitions}department`] = document(`${definitions}department`, parse(
      `ex:department a abac:AttributeDefinition ; abac:defaultValue ex:Unknown .`,
    ));

    const result = await loader.readDefinitions();
    expect(result.countQuads(null, null, null, null)).toBe(4);
  });

  it('descends into nested containers to read subtrees laid out by WebID or resource path.', async(): Promise<void> => {
    const host = `${subjects}alice.example/`;
    const profile = `${host}profile/`;
    resources[subjects] = container(subjects, [ host ]);
    resources[host] = container(host, [ profile ]);
    resources[profile] = container(profile, [ `${profile}card` ]);
    resources[`${profile}card`] = document(`${profile}card`, parse(
      `<https://alice.example/profile/card#me> ex:role ex:Doctor .`,
    ));
    const server = `${resourceAttributes}example.com/`;
    const records = `${server}records/`;
    resources[resourceAttributes] = container(resourceAttributes, [ server ]);
    resources[server] = container(server, [ records ]);
    resources[records] = container(records, [ `${records}2026` ]);
    resources[`${records}2026`] = document(`${records}2026`, parse(
      `<${baseUrl}records/2026/> ex:fileType ex:Medical ; ex:sensitivity ex:Internal .`,
    ));

    await expect(loader.readSubjectAttributes()).resolves.toEqual(expect.objectContaining({ size: 1 }));
    await expect(loader.readResourceAttributes()).resolves.toEqual(expect.objectContaining({ size: 2 }));
  });

  it('only takes a resource assignment about what its document mirrors.', async(): Promise<void> => {
    const records = `${resourceAttributes}example.com/records`;
    resources[resourceAttributes] = container(resourceAttributes, [ `${resourceAttributes}example.com/` ]);
    resources[`${resourceAttributes}example.com/`] = container(`${resourceAttributes}example.com/`, [ records ]);
    resources[records] = document(records, parse(`
      <${baseUrl}records> ex:fileType ex:Medical .
      <${baseUrl}records/> ex:fileType ex:Medical .
      <${baseUrl}records/admin/> ex:fileType ex:Administrative .
      <${baseUrl}records-2026/> ex:fileType ex:Medical .
      <${baseUrl}bob/records/> ex:fileType ex:Medical .
    `));

    await expect(loader.readResourceAttributes()).resolves.toEqual(expect.objectContaining({ size: 3 }));
    expect(logger.warn).toHaveBeenCalledWith(`Ignoring the assignments in ${records} about ${baseUrl}records-2026/, ` +
      `${baseUrl}bob/records/, as it only labels ${baseUrl}records and what lies beneath it`);
  });

  it('treats a missing container as empty, so it works before the store exists.', async(): Promise<void> => {
    await expect(loader.readRules()).resolves.toEqual(expect.objectContaining({ size: 0 }));
  });

  it('skips a listed child that no longer exists.', async(): Promise<void> => {
    resources[rules] = container(rules, [ `${rules}R001`, `${rules}gone` ]);
    resources[`${rules}R001`] = document(`${rules}R001`, parse(`<#R001> a abac:Rule .`));

    const result = await loader.readRules();
    expect(result.countQuads(null, null, null, null)).toBe(1);
  });

  it('reports a read failure that is not a missing resource.', async(): Promise<void> => {
    resources[rules] = new Error('disk on fire');
    await expect(loader.readRules()).rejects.toThrow(InternalServerError);
  });

  it('releases the container data stream so its lock does not leak.', async(): Promise<void> => {
    const representation = container(rules, []);
    const destroy = jest.spyOn(representation.data, 'destroy');
    resources[rules] = representation;

    await loader.readRules();
    expect(destroy).toHaveBeenCalledTimes(1);
  });

  it('reads the containers relative to the configured store path.', async(): Promise<void> => {
    loader = new AbacDataLoader(store, baseUrl, 'attributes/');
    await loader.readDefinitions();
    expect(store.getRepresentation).toHaveBeenCalledWith({ path: `${baseUrl}attributes/definitions/` }, {});
  });
});

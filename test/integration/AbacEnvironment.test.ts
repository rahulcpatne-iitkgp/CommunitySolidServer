import fetch from 'cross-fetch';
import { BasicRepresentation } from '../../src/http/representation/BasicRepresentation';
import type { App } from '../../src/init/App';
import type { ResourceStore } from '../../src/storage/ResourceStore';
import { joinUrl } from '../../src/util/PathUtil';
import { getPort } from '../util/Util';
import { getDefaultVariables, getPresetConfigPath, getTestConfigPath, instantiateFromConfig } from './Config';

const ADMIN = 'https://admin.example/profile/card#me';
const ALICE = 'https://alice.example/profile/card#me';

const prefixes = `
@prefix abac: <https://w3id.org/solid-abac#>.
@prefix acl:  <http://www.w3.org/ns/auth/acl#>.
@prefix ex:   <http://example.org/hospital#>.
`;

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

/**
 * The time of day the given number of minutes from now, as `HH:MM`.
 */
function fromNow(minutes: number): string {
  const moment = new Date(Date.now() + (minutes * 60 * 1000));
  return `${pad(moment.getHours())}:${pad(moment.getMinutes())}`;
}

async function getAs(url: string, webId: string): Promise<number> {
  return (await fetch(url, { headers: { authorization: `WebID ${webId}` }})).status;
}

function url(port: number, path: string): string {
  return `http://localhost:${port}/${path}`;
}

/**
 * Starts a server with the ABAC layer and the given environment policy, seeded identically in both cases.
 * The rules each grant read on one category of resource, so a refusal names the attribute that caused it.
 */
async function startServer(port: number, policy: string, variables: Record<string, unknown>): Promise<App> {
  const baseUrl = `http://localhost:${port}/`;
  const instances = await instantiateFromConfig(
    'urn:solid-server:test:Instances',
    [
      getPresetConfigPath('storage/backend/memory.json'),
      getTestConfigPath('ldp-with-abac.json'),
      getTestConfigPath(policy),
    ],
    { ...getDefaultVariables(port, baseUrl), 'urn:solid-server:custom:variable:abacAdmin': ADMIN, ...variables },
  ) as Record<string, any>;
  const { app } = instances;
  const store: ResourceStore = instances.store;
  await app.start();

  async function write(path: string, contents: string, type: string): Promise<void> {
    await store.setRepresentation({ path: joinUrl(baseUrl, path) }, new BasicRepresentation(contents, type));
  }
  async function writeAbac(path: string, turtle: string): Promise<void> {
    await write(joinUrl('.abac/', path), `${prefixes}${turtle}`, 'text/turtle');
  }

  for (const category of [ 'hours', 'network', 'proof' ]) {
    await write(`${category}/note.txt`, 'data', 'text/plain');
  }
  await writeAbac('definitions/role', `
    ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:None .`);
  await writeAbac('definitions/category', `
    ex:category a abac:AttributeDefinition ; abac:appliesTo abac:Resource ; abac:defaultValue ex:Uncategorised .`);
  await writeAbac('definitions/period', `
    abac:period a abac:AttributeDefinition ; abac:appliesTo abac:Environment ; abac:defaultValue abac:OutOfHours .`);
  await writeAbac('definitions/network', `
    abac:network a abac:AttributeDefinition ; abac:appliesTo abac:Environment ; abac:defaultValue abac:External .`);
  await writeAbac('definitions/authMethod', `
    abac:authMethod a abac:AttributeDefinition ;
      abac:appliesTo abac:Environment ; abac:defaultValue abac:NoCredentials .`);
  await writeAbac('subjects/alice.example/profile/card', `<${ALICE}> ex:role ex:Doctor .`);
  await writeAbac('resources/categories', `
    <${joinUrl(baseUrl, 'hours/')}> ex:category ex:HoursOnly .
    <${joinUrl(baseUrl, 'network/')}> ex:category ex:InternalOnly .
    <${joinUrl(baseUrl, 'proof/')}> ex:category ex:ProofOnly .`);
  await writeAbac('rules/R001', `
    <#R001> a abac:Rule ; abac:grants acl:Read ;
      abac:allOf [ ex:role ex:Doctor ], [ ex:category ex:HoursOnly ], [ abac:period abac:BusinessHours ] .`);
  await writeAbac('rules/R002', `
    <#R002> a abac:Rule ; abac:grants acl:Read ;
      abac:allOf [ ex:role ex:Doctor ], [ ex:category ex:InternalOnly ], [ abac:network abac:Internal ] .`);
  await writeAbac('rules/R003', `
    <#R003> a abac:Rule ; abac:grants acl:Read ;
      abac:allOf [ ex:role ex:Doctor ], [ ex:category ex:ProofOnly ], [ abac:authMethod abac:BoundToken ] .`);
  return app;
}

describe('An LDP handler with ABAC rules over the circumstances of a request', (): void => {
  const inside = getPort('AbacEnvironment');
  const outside = getPort('AbacEnvironmentOutside');
  let insideApp: App;
  let outsideApp: App;

  beforeAll(async(): Promise<void> => {
    insideApp = await startServer(inside, 'abac-environment.json', {
      'urn:solid-server:custom:variable:businessHoursStart': fromNow(-60),
      'urn:solid-server:custom:variable:businessHoursEnd': fromNow(60),
    });
    outsideApp = await startServer(outside, 'abac-environment-outside.json', {});
  });

  afterAll(async(): Promise<void> => {
    await insideApp.stop();
    await outsideApp.stop();
  });

  it('grants inside the business-hours window and refuses outside it.', async(): Promise<void> => {
    await expect(getAs(url(inside, 'hours/note.txt'), ALICE)).resolves.toBe(200);
    await expect(getAs(url(outside, 'hours/note.txt'), ALICE)).resolves.toBe(403);
  });

  it('grants from the internal network and refuses from outside it.', async(): Promise<void> => {
    await expect(getAs(url(inside, 'network/note.txt'), ALICE)).resolves.toBe(200);
    await expect(getAs(url(outside, 'network/note.txt'), ALICE)).resolves.toBe(403);
  });

  it('refuses a rule demanding a key-bound token on a server that cannot prove one.', async(): Promise<void> => {
    await expect(getAs(url(inside, 'proof/note.txt'), ALICE)).resolves.toBe(403);
    await expect(getAs(url(outside, 'proof/note.txt'), ALICE)).resolves.toBe(403);
  });
});

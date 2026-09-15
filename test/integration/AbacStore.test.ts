import fetch from 'cross-fetch';
import { BasicRepresentation } from '../../src/http/representation/BasicRepresentation';
import type { App } from '../../src/init/App';
import type { ResourceStore } from '../../src/storage/ResourceStore';
import { joinUrl } from '../../src/util/PathUtil';
import { AcpHelper } from '../util/AcpHelper';
import { getPort } from '../util/Util';
import { getDefaultVariables, getPresetConfigPath, getTestConfigPath, instantiateFromConfig } from './Config';

const port = getPort('AbacStore');
const baseUrl = `http://localhost:${port}/`;

const ADMIN = 'https://admin.example/profile/card#me';
const OWNER = 'https://owner.example/profile/card#me';
const ALICE = 'https://alice.example/profile/card#me';

const prefixes = `
@prefix abac: <https://w3id.org/solid-abac#>.
@prefix acl:  <http://www.w3.org/ns/auth/acl#>.
@prefix ex:   <http://example.org/hospital#>.
`;

/**
 * Sends a request as the given agent, using the debug WebID authorization header, and returns its status.
 */
async function send(url: string, webId?: string, method = 'GET', turtle?: string): Promise<number> {
  const headers: Record<string, string> = webId ? { authorization: `WebID ${webId}` } : {};
  if (turtle) {
    headers['content-type'] = 'text/turtle';
  }
  return (await fetch(url, { method, headers, body: turtle && `${prefixes}${turtle}` })).status;
}

describe('An LDP handler with the ABAC store guarded by its administrator', (): void => {
  let app: App;

  const abac = joinUrl(baseUrl, '.abac/');
  const definition = joinUrl(abac, 'definitions/role');
  const subject = joinUrl(abac, 'subjects/alice.example/profile/card');
  const resource = joinUrl(abac, 'resources/records');
  const rule = joinUrl(abac, 'rules/R001');
  const data = joinUrl(baseUrl, 'records/data.txt');

  beforeAll(async(): Promise<void> => {
    const instances = await instantiateFromConfig(
      'urn:solid-server:test:Instances',
      [ getPresetConfigPath('storage/backend/memory.json'), getTestConfigPath('ldp-with-abac.json') ],
      { ...getDefaultVariables(port, baseUrl), 'urn:solid-server:custom:variable:abacAdmin': ADMIN },
    ) as Record<string, any>;
    ({ app } = instances);
    const store: ResourceStore = instances.store;
    await app.start();

    // The owner has full control over the root and everything in it, the administrator nothing.
    await store.setRepresentation({ path: data }, new BasicRepresentation('owned data', 'text/plain'));
    const acpHelper = new AcpHelper(store);
    const policy = acpHelper.createPolicy({
      allow: [ 'read', 'append', 'write', 'control' ],
      anyOf: [ acpHelper.createMatcher({ agent: `<${OWNER}>` }) ],
    });
    await acpHelper.setAcp(baseUrl, acpHelper.createAcr({
      resource: baseUrl,
      policies: [ policy ],
      memberPolicies: [ policy ],
    }));
  });

  afterAll(async(): Promise<void> => {
    await app.stop();
  });

  it('lets the administrator create every part of the store from nothing.', async(): Promise<void> => {
    await expect(send(abac, ADMIN)).resolves.toBe(404);
    const documents = {
      [definition]: 'ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:None .',
      [subject]: `<${ALICE}> ex:role ex:Doctor .`,
      [resource]: `<${joinUrl(baseUrl, 'records/')}> ex:category ex:Medical .`,
      [rule]: '<#R001> a abac:Rule ; abac:grants acl:Read ; abac:allOf [ ex:role ex:Doctor ] .',
    };
    for (const [ url, turtle ] of Object.entries(documents)) {
      await expect(send(url, ADMIN, 'PUT', turtle)).resolves.toBe(201);
    }
  });

  it('refuses writes to the store from everyone else, the owner included.', async(): Promise<void> => {
    const writes: [string, string, string?][] = [
      [ subject, 'PUT', `<${ALICE}> ex:role ex:Surgeon .` ],
      [ joinUrl(abac, 'rules/R002'), 'PUT', '<#R002> a abac:Rule ; abac:grants acl:Write .' ],
      [ `${rule}.acr`, 'PUT', `<#policy> acl:agent <${ALICE}> .` ],
      [ rule, 'DELETE' ],
    ];
    for (const [ url, method, turtle ] of writes) {
      await expect(send(url, OWNER, method, turtle)).resolves.toBe(403);
      await expect(send(url, ALICE, method, turtle)).resolves.toBe(403);
      await expect(send(url, undefined, method, turtle)).resolves.toBe(401);
    }
  });

  it('lets anyone read the definitions and rules.', async(): Promise<void> => {
    for (const url of [ definition, rule ]) {
      await expect(send(url)).resolves.toBe(200);
      await expect(send(url, ALICE)).resolves.toBe(200);
    }
  });

  it('keeps the rest of the store private to the administrator.', async(): Promise<void> => {
    for (const url of [ abac, subject, resource ]) {
      await expect(send(url)).resolves.toBe(401);
      await expect(send(url, ALICE)).resolves.toBe(403);
      await expect(send(url, OWNER)).resolves.toBe(403);
      await expect(send(url, ADMIN)).resolves.toBe(200);
    }
  });

  it('gives the administrator no access to data just for being the administrator.', async(): Promise<void> => {
    await expect(send(data, OWNER)).resolves.toBe(200);
    await expect(send(data, ALICE)).resolves.toBe(200);
    await expect(send(data, ADMIN)).resolves.toBe(403);
  });
});

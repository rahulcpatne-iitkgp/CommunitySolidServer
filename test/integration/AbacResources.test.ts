import fetch from 'cross-fetch';
import { BasicRepresentation } from '../../src/http/representation/BasicRepresentation';
import type { App } from '../../src/init/App';
import type { ResourceStore } from '../../src/storage/ResourceStore';
import { joinUrl } from '../../src/util/PathUtil';
import { getPort } from '../util/Util';
import { getDefaultVariables, getPresetConfigPath, getTestConfigPath, instantiateFromConfig } from './Config';

const port = getPort('AbacResources');
const baseUrl = `http://localhost:${port}/`;

const ADMIN = 'https://admin.example/profile/card#me';
const ALICE = 'https://alice.example/profile/card#me';
const BOB = 'https://bob.example/profile/card#me';

const prefixes = `
@prefix abac: <https://w3id.org/solid-abac#>.
@prefix acl:  <http://www.w3.org/ns/auth/acl#>.
@prefix ex:   <http://example.org/hospital#>.
`;

/**
 * Sends a request as the given agent, using the debug WebID authorization header, and returns its status.
 */
async function send(url: string, webId: string, method = 'GET', text?: string): Promise<number> {
  const headers: Record<string, string> = { authorization: `WebID ${webId}` };
  if (text) {
    headers['content-type'] = 'text/plain';
  }
  return (await fetch(url, { method, headers, body: text })).status;
}

describe('An LDP handler with ABAC rules over resource attributes', (): void => {
  let app: App;
  let store: ResourceStore;

  const note = joinUrl(baseUrl, 'records/2026/note.txt');
  const rota = joinUrl(baseUrl, 'records/admin/rota.txt');
  const photo = joinUrl(baseUrl, 'holiday-photos/img.jpg');

  async function write(url: string, contents: string, type: string): Promise<void> {
    await store.setRepresentation({ path: url }, new BasicRepresentation(contents, type));
  }

  async function writeAbac(path: string, turtle: string): Promise<void> {
    await write(joinUrl(baseUrl, '.abac/', path), `${prefixes}${turtle}`, 'text/turtle');
  }

  beforeAll(async(): Promise<void> => {
    const instances = await instantiateFromConfig(
      'urn:solid-server:test:Instances',
      [ getPresetConfigPath('storage/backend/memory.json'), getTestConfigPath('ldp-with-abac.json') ],
      { ...getDefaultVariables(port, baseUrl), 'urn:solid-server:custom:variable:abacAdmin': ADMIN },
    ) as Record<string, any>;
    ({ app, store } = instances);
    await app.start();

    // No ACRs, so only ABAC can grant access. Alice's assignments and those of `records/` also claim an attribute
    // describing the other kind of entity, which must be ignored.
    for (const url of [ note, rota, photo ]) {
      await write(url, 'data', 'text/plain');
    }
    await writeAbac('definitions/role', `
      ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:None .`);
    await writeAbac('definitions/category', `
      ex:category a abac:AttributeDefinition ; abac:appliesTo abac:Resource ; abac:defaultValue ex:Uncategorised .`);
    await writeAbac('subjects/alice.example/profile/card', `<${ALICE}> ex:role ex:Doctor ; ex:category ex:Medical .`);
    await writeAbac('subjects/bob.example/profile/card', `<${BOB}> ex:role ex:Nurse .`);
    await writeAbac('resources/records', `
      <${joinUrl(baseUrl, 'records/')}> ex:category ex:Medical ; ex:role ex:Doctor .
      <${joinUrl(baseUrl, 'records/admin/')}> ex:category ex:Administrative .`);
    await writeAbac('rules/R001', `
      <#R001> a abac:Rule ; abac:grants acl:Read, acl:Write ;
        abac:allOf [ ex:role ex:Doctor ], [ ex:category ex:Medical ] .`);
  });

  afterAll(async(): Promise<void> => {
    await app.stop();
  });

  it('scopes a grant to the resources that inherit a matching attribute.', async(): Promise<void> => {
    await expect(send(note, ALICE)).resolves.toBe(200);
    await expect(send(joinUrl(baseUrl, 'holiday-photos/'), ALICE)).resolves.toBe(403);
  });

  it('lets a descendant override the value its container assigns.', async(): Promise<void> => {
    await expect(send(rota, ALICE)).resolves.toBe(403);
  });

  it('resolves a resource that does not exist yet against its would-be ancestors.', async(): Promise<void> => {
    await expect(send(joinUrl(baseUrl, 'records/2027/q1/new.txt'), ALICE, 'PUT', 'new')).resolves.toBe(201);
    await expect(send(joinUrl(baseUrl, 'holiday-photos/2027/new.txt'), ALICE, 'PUT', 'new')).resolves.toBe(403);
  });

  it('resolves each attribute only against the kind of entity its definition applies to.', async(): Promise<void> => {
    await expect(send(photo, ALICE)).resolves.toBe(403);
    await expect(send(note, BOB)).resolves.toBe(403);
  });

  it('resolves a newly defined attribute to its default on every existing resource.', async(): Promise<void> => {
    await expect(send(photo, BOB)).resolves.toBe(403);
    await writeAbac('definitions/sensitivity', `
      ex:sensitivity a abac:AttributeDefinition ; abac:appliesTo abac:Resource ; abac:defaultValue ex:Internal .`);
    await writeAbac('rules/R002', `
      <#R002> a abac:Rule ; abac:grants acl:Read ;
        abac:allOf [ ex:role ex:Nurse ], [ ex:sensitivity ex:Internal ] .`);
    await expect(send(photo, BOB)).resolves.toBe(200);
  });
});

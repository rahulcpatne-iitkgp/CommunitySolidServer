import fetch from 'cross-fetch';
import { BasicRepresentation } from '../../src/http/representation/BasicRepresentation';
import type { App } from '../../src/init/App';
import type { ResourceStore } from '../../src/storage/ResourceStore';
import { joinUrl } from '../../src/util/PathUtil';
import { AcpHelper } from '../util/AcpHelper';
import { getPort } from '../util/Util';
import { getDefaultVariables, getPresetConfigPath, getTestConfigPath, instantiateFromConfig } from './Config';

const port = getPort('AbacServer');
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
async function send(url: string, webId?: string, method = 'GET', turtle?: string): Promise<number> {
  const headers: Record<string, string> = webId ? { authorization: `WebID ${webId}` } : {};
  if (turtle) {
    headers['content-type'] = 'text/turtle';
  }
  return (await fetch(url, { method, headers, body: turtle })).status;
}

describe('An LDP handler with the grant-only ABAC layer', (): void => {
  let app: App;
  let store: ResourceStore;

  const target = joinUrl(baseUrl, 'records/note.ttl');
  const bobsResource = joinUrl(baseUrl, 'records/bobs.txt');

  async function write(path: string, contents: string, type = 'text/turtle'): Promise<void> {
    await store.setRepresentation({ path }, new BasicRepresentation(contents, type));
  }

  beforeAll(async(): Promise<void> => {
    const instances = await instantiateFromConfig(
      'urn:solid-server:test:Instances',
      [ getPresetConfigPath('storage/backend/memory.json'), getTestConfigPath('ldp-with-abac.json') ],
      { ...getDefaultVariables(port, baseUrl), 'urn:solid-server:custom:variable:abacAdmin': ADMIN },
    ) as Record<string, any>;
    ({ app, store } = instances);
    await app.start();

    // `target` has no ACR, so only the ABAC layer can grant read on it.
    await write(target, 'patient note', 'text/plain');
    await write(bobsResource, 'readable by bob', 'text/plain');
    const acpHelper = new AcpHelper(store);
    await acpHelper.setAcp(bobsResource, acpHelper.createAcr({
      resource: bobsResource,
      policies: [ acpHelper.createPolicy({
        allow: [ 'read' ],
        anyOf: [ acpHelper.createMatcher({ agent: `<${BOB}>` }) ],
      }) ],
    }));

    await write(joinUrl(baseUrl, '.abac/definitions/role'), `${prefixes}
      ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:None .`);
    await write(joinUrl(baseUrl, '.abac/subjects/alice.example/profile/card'), `${prefixes}
      <${ALICE}> ex:role ex:Doctor .`);
    await write(joinUrl(baseUrl, '.abac/subjects/bob.example/profile/card'), `${prefixes}
      <${BOB}> ex:role ex:Nurse .`);
    await write(joinUrl(baseUrl, '.abac/rules/R001'), `${prefixes}
      <#R001> a abac:Rule ; abac:grants acl:Read, acl:Write ; abac:allOf [ ex:role ex:Doctor ] .`);
    await write(joinUrl(baseUrl, '.abac/rules/R002'), `${prefixes}
      <#R002> a abac:Rule ; abac:grants acl:Control ; abac:allOf [ ex:role ex:Nurse ] .`);
  });

  afterAll(async(): Promise<void> => {
    await app.stop();
  });

  it('grants access to an agent no policy mentions, when a rule matches them.', async(): Promise<void> => {
    await expect(send(target, ALICE)).resolves.toBe(200);
  });

  it('leaves an agent whose attributes match no rule unaffected.', async(): Promise<void> => {
    await expect(send(target, BOB)).resolves.toBe(403);
  });

  it('leaves an unidentified agent unaffected.', async(): Promise<void> => {
    await expect(send(target)).resolves.toBe(401);
  });

  it('does not remove access that ACP granted.', async(): Promise<void> => {
    await expect(send(bobsResource, BOB)).resolves.toBe(200);
  });

  it('lets a rule granting Write create and delete resources.', async(): Promise<void> => {
    const created = joinUrl(baseUrl, 'records/new/note.ttl');
    await expect(send(created, ALICE, 'PUT', '<> a <#Note> .')).resolves.toBe(201);
    await expect(send(created, ALICE, 'DELETE')).resolves.toBe(205);
  });

  it('gives access to an ACR only through Control, as ACP does.', async(): Promise<void> => {
    const acr = `${bobsResource}.acr`;
    await expect(send(acr, ALICE)).resolves.toBe(403);
    await expect(send(acr, ALICE, 'PUT', '<#policy> a <#Policy> .')).resolves.toBe(403);
    await expect(send(acr, BOB)).resolves.toBe(200);
  });

  it('cannot grant access to the server internals, whatever the rules say.', async(): Promise<void> => {
    await expect(send(joinUrl(baseUrl, '.internal/'), ALICE)).resolves.not.toBe(200);
  });

  it('cannot grant access to the ABAC store itself.', async(): Promise<void> => {
    await expect(send(joinUrl(baseUrl, '.abac/subjects/alice.example/profile/card'), ALICE)).resolves.not.toBe(200);
  });
});

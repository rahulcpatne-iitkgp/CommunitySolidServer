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

const ALICE = 'https://alice.example/profile/card#me';
const BOB = 'https://bob.example/profile/card#me';

const prefixes = `
@prefix abac: <https://w3id.org/solid-abac#>.
@prefix acl:  <http://www.w3.org/ns/auth/acl#>.
@prefix ex:   <http://example.org/hospital#>.
`;

/**
 * Requests the resource as the given agent, using the debug WebID authorization header.
 */
async function getAs(url: string, webId?: string): Promise<number> {
  const headers = webId ? { authorization: `WebID ${webId}` } : undefined;
  return (await fetch(url, { headers })).status;
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
      getDefaultVariables(port, baseUrl),
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
      <#R001> a abac:Rule ; abac:grants acl:Read ; abac:allOf [ ex:role ex:Doctor ] .`);
  });

  afterAll(async(): Promise<void> => {
    await app.stop();
  });

  it('grants access to an agent no policy mentions, when a rule matches them.', async(): Promise<void> => {
    await expect(getAs(target, ALICE)).resolves.toBe(200);
  });

  it('leaves an agent whose attributes match no rule unaffected.', async(): Promise<void> => {
    await expect(getAs(target, BOB)).resolves.toBe(403);
  });

  it('leaves an unidentified agent unaffected.', async(): Promise<void> => {
    await expect(getAs(target)).resolves.toBe(401);
  });

  it('does not remove access that ACP granted.', async(): Promise<void> => {
    await expect(getAs(bobsResource, BOB)).resolves.toBe(200);
  });

  it('cannot grant access to the server internals, whatever the rules say.', async(): Promise<void> => {
    await expect(getAs(joinUrl(baseUrl, '.internal/'), ALICE)).resolves.not.toBe(200);
  });

  it('cannot grant access to the ABAC store itself.', async(): Promise<void> => {
    await expect(getAs(joinUrl(baseUrl, '.abac/subjects/alice.example/profile/card'), ALICE)).resolves.not.toBe(200);
  });
});

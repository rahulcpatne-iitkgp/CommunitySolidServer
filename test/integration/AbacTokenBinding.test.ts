import type { KeyPair } from '@inrupt/solid-client-authn-core';
import { createDpopHeader, generateDpopKeyPair } from '@inrupt/solid-client-authn-core';
import fetch from 'cross-fetch';
import { BasicRepresentation } from '../../src/http/representation/BasicRepresentation';
import type { App } from '../../src/init/App';
import type { ResourceStore } from '../../src/storage/ResourceStore';
import { APPLICATION_X_WWW_FORM_URLENCODED } from '../../src/util/ContentTypes';
import { joinUrl } from '../../src/util/PathUtil';
import { register } from '../util/AccountUtil';
import { getPort } from '../util/Util';
import { getDefaultVariables, getTestConfigPath, instantiateFromConfig } from './Config';

const port = getPort('AbacTokenBinding');
const baseUrl = `http://localhost:${port}/`;
const tokenUrl = joinUrl(baseUrl, '.oidc/token');
const target = joinUrl(baseUrl, 'records/note.txt');

const ADMIN = 'https://admin.example/profile/card#me';

const prefixes = `
@prefix abac: <https://w3id.org/solid-abac#>.
@prefix acl:  <http://www.w3.org/ns/auth/acl#>.
@prefix ex:   <http://example.org/hospital#>.
`;

describe('An LDP handler with an ABAC rule over how an identity was proven', (): void => {
  let app: App;
  let store: ResourceStore;
  let dpopKey: KeyPair;
  let credentials: { id: string; secret: string };

  /**
   * Requests an access token for the registered client credentials.
   * It is bound to `dpopKey` only when a proof is sent along with the request, which is what this suite varies.
   */
  async function requestToken(bound: boolean): Promise<string> {
    const authString = `${encodeURIComponent(credentials.id)}:${encodeURIComponent(credentials.secret)}`;
    const headers: Record<string, string> = {
      authorization: `Basic ${Buffer.from(authString).toString('base64')}`,
      'content-type': APPLICATION_X_WWW_FORM_URLENCODED,
    };
    if (bound) {
      headers.dpop = await createDpopHeader(tokenUrl, 'POST', dpopKey);
    }
    const res = await fetch(tokenUrl, { method: 'POST', headers, body: 'grant_type=client_credentials&scope=webid' });
    expect(res.status).toBe(200);
    return (await res.json()).access_token;
  }

  beforeAll(async(): Promise<void> => {
    const instances = await instantiateFromConfig(
      'urn:solid-server:test:Instances',
      getTestConfigPath('server-memory-abac.json'),
      { ...getDefaultVariables(port, baseUrl), 'urn:solid-server:custom:variable:abacAdmin': ADMIN },
    ) as Record<string, any>;
    ({ app, store } = instances);
    await app.start();

    dpopKey = await generateDpopKeyPair();
    const { webId, authorization, controls } = await register(baseUrl, {
      email: 'alice@example.com',
      password: 'alice-secret',
      podName: 'alice',
    });
    const res = await fetch(controls.account.clientCredentials, {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'token', webId }),
    });
    if (res.status !== 200) {
      throw new Error(`Error creating client credentials: ${await res.text()}`);
    }
    credentials = await res.json();

    // The target sits outside alice's pod and has no ACR, so only a rule can allow access to it.
    async function writeAbac(path: string, turtle: string): Promise<void> {
      await store.setRepresentation(
        { path: joinUrl(baseUrl, '.abac/', path) },
        new BasicRepresentation(`${prefixes}${turtle}`, 'text/turtle'),
      );
    }
    await store.setRepresentation({ path: target }, new BasicRepresentation('patient note', 'text/plain'));
    await writeAbac('definitions/role', `
      ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ;
        abac:value ex:None, ex:Doctor ; abac:defaultValue ex:None .`);
    await writeAbac('definitions/fileType', `
      ex:fileType a abac:AttributeDefinition ; abac:appliesTo abac:Resource ;
        abac:value ex:Unspecified, ex:Medical ; abac:defaultValue ex:Unspecified .`);
    await writeAbac('definitions/authMethod', `
      abac:authMethod a abac:AttributeDefinition ; abac:appliesTo abac:Environment ;
        abac:value abac:BoundToken, abac:BearerToken, abac:Unsecure, abac:NoCredentials ;
        abac:defaultValue abac:NoCredentials .`);
    await writeAbac('subjects/alice', `<${webId}> ex:role ex:Doctor .`);
    await writeAbac('resources/localhost/records', `
      <${joinUrl(baseUrl, 'records/')}> ex:fileType ex:Medical .`);
    await writeAbac('rules/R001', `
      <#R001> a abac:Rule ; abac:allow acl:Read ;
        abac:allOf [ ex:role ex:Doctor ], [ ex:fileType ex:Medical ], [ abac:authMethod abac:BoundToken ] .`);
  });

  afterAll(async(): Promise<void> => {
    await app.stop();
  });

  it('allows when the identity is proven with a key-bound token.', async(): Promise<void> => {
    const accessToken = await requestToken(true);
    const res = await fetch(target, {
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: await createDpopHeader(target, 'GET', dpopKey),
      },
    });
    expect(res.status).toBe(200);
  });

  it('refuses the same request when the token is a plain bearer token.', async(): Promise<void> => {
    const accessToken = await requestToken(false);
    const res = await fetch(target, { headers: { authorization: `Bearer ${accessToken}` }});
    expect(res.status).toBe(403);
  });
});

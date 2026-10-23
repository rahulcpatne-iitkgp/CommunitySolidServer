import type { IMatcher, IPolicy } from '@solid/access-control-policy';
import fetch from 'cross-fetch';
import { BasicRepresentation } from '../../src/http/representation/BasicRepresentation';
import type { App } from '../../src/init/App';
import type { ResourceStore } from '../../src/storage/ResourceStore';
import { joinUrl } from '../../src/util/PathUtil';
import { register } from '../util/AccountUtil';
import { AcpHelper } from '../util/AcpHelper';
import { getPort } from '../util/Util';
import { getDefaultVariables, getTestConfigPath, instantiateFromConfig } from './Config';

const port = getPort('AbacOwnerVeto');
const baseUrl = `http://localhost:${port}/`;

const ADMIN = 'https://admin.example/profile/card#me';
const ALICE = 'https://alice.example/profile/card#me';
const CAROL = 'https://carol.example/profile/card#me';
const BOB = 'https://bob.example/profile/card#me';

const prefixes = `
@prefix abac: <https://w3id.org/solid-abac#>.
@prefix acl:  <http://www.w3.org/ns/auth/acl#>.
@prefix ex:   <http://example.org/hospital#>.
`;
const record = '<> a <#Record> .';

/**
 * The document in the ABAC store that labels the pod with the given name.
 */
function labels(podName: string): string {
  return joinUrl(baseUrl, `.abac/resources/localhost/${podName}`);
}

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

describe('An LDP handler whose ABAC grants a pod owner can veto', (): void => {
  let app: App;
  let store: ResourceStore;
  let acp: AcpHelper;
  let owner: string;
  let pod: string;
  let records: string;
  let note: string;
  let neighbour: string;
  let neighbourNote: string;

  /**
   * A matcher for the given agent, or for everyone.
   */
  function agent(webId?: string): IMatcher {
    return acp.createMatcher(webId ? { agent: `<${webId}>` } : { publicAgent: true });
  }

  /**
   * Has the owner replace the ACR of the given resource over HTTP, and returns the status.
   */
  async function setAcr(resource: string, policies?: IPolicy[], memberPolicies?: IPolicy[]): Promise<number> {
    return send(`${resource}.acr`, owner, 'PUT', acp.toTurtle(acp.createAcr({ resource, policies, memberPolicies })));
  }

  async function write(path: string, contents: string): Promise<void> {
    await store.setRepresentation({ path }, new BasicRepresentation(`${prefixes}${contents}`, 'text/turtle'));
  }

  beforeAll(async(): Promise<void> => {
    const instances = await instantiateFromConfig(
      'urn:solid-server:test:Instances',
      getTestConfigPath('server-memory-abac-unsafe.json'),
      { ...getDefaultVariables(port, baseUrl), 'urn:solid-server:custom:variable:abacAdmin': ADMIN },
    ) as Record<string, any>;
    ({ app, store } = instances);
    await app.start();
    acp = new AcpHelper(store);

    // The pod's own ACR gives its owner everything and mentions nobody else.
    const user = { email: 'owner@example.com', password: 'password', podName: 'owner' };
    ({ pod, webId: owner } = await register(baseUrl, user));
    records = joinUrl(pod, 'records/');
    note = joinUrl(records, 'note.ttl');
    let neighbourPod: string;
    const other = { ...user, email: 'neighbour@example.com', podName: 'neighbour' };
    ({ pod: neighbourPod, webId: neighbour } = await register(baseUrl, other));
    neighbourNote = joinUrl(neighbourPod, 'records/note.ttl');
    for (const path of [ note, joinUrl(records, 'other.ttl'), joinUrl(pod, 'shared.ttl'), neighbourNote ]) {
      await write(path, record);
    }

    await write(joinUrl(baseUrl, '.abac/definitions/role'), `
      ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ;
        abac:value ex:None, ex:Doctor ; abac:defaultValue ex:None .`);
    await write(joinUrl(baseUrl, '.abac/definitions/category'), `
      ex:category a abac:AttributeDefinition ; abac:appliesTo abac:Resource ;
        abac:value ex:Uncategorised, ex:Medical ; abac:defaultValue ex:Uncategorised .`);
    await write(joinUrl(baseUrl, '.abac/subjects/doctors'), `
      <${ALICE}> ex:role ex:Doctor . <${CAROL}> ex:role ex:Doctor .`);
    // The owner's labels also claim the neighbour's records, which a document mirroring the owner's pod cannot label.
    await send(labels('owner'), ADMIN, 'PUT', `${prefixes}
      <${pod}> ex:category ex:Medical .
      <${joinUrl(neighbourPod, 'records/')}> ex:category ex:Medical .`);
    await send(labels('neighbour'), ADMIN, 'PUT', `${prefixes}
      <${neighbourPod}> ex:category ex:Uncategorised .`);
    await write(joinUrl(baseUrl, '.abac/rules/R001'), `
      <#R001> a abac:Rule ; abac:grants acl:Read, acl:Write, acl:Control ;
        abac:allOf [ ex:role ex:Doctor ], [ ex:category ex:Medical ] .`);
  });

  afterAll(async(): Promise<void> => {
    await app.stop();
  });

  it('refuses a grant the owner denies, for that mode and agent only, until they lift it.', async(): Promise<void> => {
    await expect(send(note, ALICE)).resolves.toBe(200);

    await expect(setAcr(note, [ acp.createPolicy({ deny: [ 'read' ], anyOf: [ agent(ALICE) ]}) ])).resolves.toBe(201);
    await expect(send(note, ALICE)).resolves.toBe(403);
    await expect(send(note, CAROL)).resolves.toBe(200);
    await expect(send(note, ALICE, 'PUT', record)).resolves.toBe(205);

    await expect(setAcr(note)).resolves.toBe(205);
    await expect(send(note, ALICE)).resolves.toBe(200);
  });

  it('puts the veto beyond the reach of a rule that grants Control.', async(): Promise<void> => {
    await expect(setAcr(note, [ acp.createPolicy({ deny: [ 'read' ], anyOf: [ agent(ALICE) ]}) ])).resolves.toBe(205);
    const lifted = acp.toTurtle(acp.createAcr({ resource: note }));
    await expect(send(`${note}.acr`, CAROL)).resolves.toBe(403);
    await expect(send(`${note}.acr`, CAROL, 'PUT', lifted)).resolves.toBe(403);
    await expect(send(note, ALICE)).resolves.toBe(403);
  });

  it('lets the policies on a container veto the grant on it and on its members.', async(): Promise<void> => {
    const other = joinUrl(records, 'other.ttl');
    const created = joinUrl(records, 'new.ttl');
    await expect(setAcr(
      records,
      [ acp.createPolicy({ deny: [ 'write' ], anyOf: [ agent(ALICE) ]}) ],
      [ acp.createPolicy({ deny: [ 'read' ], anyOf: [ agent(ALICE) ]}) ],
    )).resolves.toBe(201);

    await expect(send(records, ALICE)).resolves.toBe(200);
    await expect(send(other, ALICE)).resolves.toBe(403);
    await expect(send(other, ALICE, 'PUT', record)).resolves.toBe(205);
    await expect(send(created, ALICE, 'PUT', record)).resolves.toBe(403);
    await expect(send(other, ALICE, 'DELETE')).resolves.toBe(403);
    await expect(send(created, CAROL, 'PUT', record)).resolves.toBe(201);
  });

  it('treats only an explicit denial as a veto.', async(): Promise<void> => {
    const shared = joinUrl(pod, 'shared.ttl');
    const everyoneButAlice = acp.createPolicy({ allow: [ 'read' ], anyOf: [ agent() ], noneOf: [ agent(ALICE) ]});
    await expect(setAcr(shared, [ everyoneButAlice ])).resolves.toBe(201);

    await expect(send(shared, BOB)).resolves.toBe(200);
    await expect(send(shared, ALICE)).resolves.toBe(200);
  });

  it('lets an owner read the labels on their own pod, and on no other.', async(): Promise<void> => {
    await expect(send(labels('owner'), owner)).resolves.toBe(200);
    await expect(send(labels('owner'), owner, 'PUT', record)).resolves.toBe(403);
    await expect(send(labels('neighbour'), owner)).resolves.toBe(403);
    await expect(send(labels('neighbour'), neighbour)).resolves.toBe(200);
    await expect(send(joinUrl(baseUrl, '.abac/resources/localhost/'), owner)).resolves.toBe(403);
    await expect(send(labels('owner'), ALICE)).resolves.toBe(403);
    await expect(send(labels('owner'))).resolves.toBe(401);
  });

  it('ignores a label filed under one pod about a resource in another.', async(): Promise<void> => {
    await expect(send(neighbourNote, ALICE)).resolves.toBe(403);
  });

  it('leaves the owner their own ACR, even when they deny themselves.', async(): Promise<void> => {
    const denyEveryone = acp.createPolicy({ deny: [ 'read', 'write', 'control' ], anyOf: [ agent() ]});
    await expect(setAcr(note, [ denyEveryone ])).resolves.toBe(205);
    await expect(send(note, ALICE)).resolves.toBe(403);
    await expect(send(note, owner)).resolves.toBe(403);

    await expect(send(`${note}.acr`, owner)).resolves.toBe(200);
    await expect(setAcr(note)).resolves.toBe(205);
    await expect(send(note, owner)).resolves.toBe(200);
  });
});

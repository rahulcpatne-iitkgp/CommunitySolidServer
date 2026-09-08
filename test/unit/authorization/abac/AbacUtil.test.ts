import { DataFactory, Parser, Store } from 'n3';
import {
  buildAttributeVector,
  getAttributeDefinitions,
  getRules,
} from '../../../../src/authorization/abac/AbacUtil';
import { ABAC } from '../../../../src/util/Vocabularies';
import namedNode = DataFactory.namedNode;

describe('AbacUtil', (): void => {
  const baseUrl = 'http://example.com/';
  const alice = `${baseUrl}alice/profile/card#me`;
  const ex = 'http://example.org/hospital#';
  const acl = 'http://www.w3.org/ns/auth/acl#';

  function parse(turtle: string): Store {
    return new Store(new Parser({ format: 'Turtle', baseIRI: baseUrl }).parse(`
    @prefix abac: <https://w3id.org/solid-abac#>.
    @prefix acl: <http://www.w3.org/ns/auth/acl#>.
    @prefix ex: <http://example.org/hospital#>.
    ${turtle}`));
  }

  // `department` declares no appliesTo, `category` a non-subject one, and `broken` no default.
  const definitions = parse(`
    ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:None .
    ex:department a abac:AttributeDefinition ; abac:defaultValue ex:Unknown .
    ex:category a abac:AttributeDefinition ; abac:appliesTo abac:Resource ; abac:defaultValue ex:Any .
    ex:broken a abac:AttributeDefinition ; abac:appliesTo abac:Subject .
  `);

  const rules = parse(`
    <#R001> a abac:Rule ;
      abac:grants acl:Read, acl:Write ;
      abac:allOf  [ a ex:Condition ; ex:role ex:Doctor ; ex:status ex:Active ] ;
      abac:anyOf  [ ex:department ex:Cardiology, ex:Emergency ] ;
      abac:noneOf [ ex:status ex:Suspended ] .
    <#R002> a abac:Rule ; abac:grants acl:Read .
  `);

  describe('#getAttributeDefinitions', (): void => {
    it('returns every definition that declares a default value.', (): void => {
      expect([ ...getAttributeDefinitions(definitions) ]).toEqual([
        { iri: `${ex}role`, appliesTo: ABAC.Subject, defaultValue: `${ex}None` },
        { iri: `${ex}department`, appliesTo: ABAC.Subject, defaultValue: `${ex}Unknown` },
        { iri: `${ex}category`, appliesTo: `${ABAC.namespace}Resource`, defaultValue: `${ex}Any` },
      ]);
    });

    it('returns nothing if no data is found.', (): void => {
      expect([ ...getAttributeDefinitions(new Store()) ]).toEqual([]);
    });
  });

  describe('#getRules', (): void => {
    it('returns every rule with its values grouped per attribute.', (): void => {
      expect([ ...getRules(rules) ]).toEqual([
        {
          iri: `${baseUrl}#R001`,
          grants: new Set([ `${acl}Read`, `${acl}Write` ]),
          allOf: [
            { attribute: `${ex}role`, values: [ `${ex}Doctor` ]},
            { attribute: `${ex}status`, values: [ `${ex}Active` ]},
          ],
          anyOf: [{ attribute: `${ex}department`, values: [ `${ex}Cardiology`, `${ex}Emergency` ]}],
          noneOf: [{ attribute: `${ex}status`, values: [ `${ex}Suspended` ]}],
        },
        {
          iri: `${baseUrl}#R002`,
          grants: new Set([ `${acl}Read` ]),
          allOf: [],
          anyOf: [],
          noneOf: [],
        },
      ]);
    });

    it('returns nothing if no data is found.', (): void => {
      expect([ ...getRules(new Store()) ]).toEqual([]);
    });
  });

  describe('#buildAttributeVector', (): void => {
    const defined = [ ...getAttributeDefinitions(definitions) ];

    it('uses the assigned value where there is one, the default otherwise.', (): void => {
      const assignments = parse(`<${alice}> ex:role ex:Doctor ; ex:clearance ex:High .`);
      expect(buildAttributeVector(defined, assignments, namedNode(alice))).toEqual({
        [`${ex}role`]: `${ex}Doctor`,
        [`${ex}department`]: `${ex}Unknown`,
        [`${ex}category`]: `${ex}Any`,
      });
    });

    it('resolves every attribute for an entity that was never assigned anything.', (): void => {
      expect(buildAttributeVector(defined, new Store(), namedNode(alice))).toEqual({
        [`${ex}role`]: `${ex}None`,
        [`${ex}department`]: `${ex}Unknown`,
        [`${ex}category`]: `${ex}Any`,
      });
    });
  });
});

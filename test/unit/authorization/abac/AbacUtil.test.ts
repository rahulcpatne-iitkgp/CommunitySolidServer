import type { NamedNode } from '@rdfjs/types';
import { DataFactory, Parser, Store } from 'n3';
import {
  buildAttributeVector,
  buildEnvironmentVector,
  getAttributeDefinitions,
  getMirroredResource,
  getRules,
  isWithin,
} from '../../../../src/authorization/abac/AbacUtil';
import type { AttributeDefinition } from '../../../../src/authorization/abac/AbacTypes';
import type { Logger } from '../../../../src/logging/Logger';
import { getLoggerFor } from '../../../../src/logging/LogUtil';
import { ABAC } from '../../../../src/util/Vocabularies';
import namedNode = DataFactory.namedNode;

jest.mock('../../../../src/logging/LogUtil', (): any => {
  const logger: Logger = { warn: jest.fn() } as any;
  return { getLoggerFor: (): Logger => logger };
});

describe('AbacUtil', (): void => {
  const logger: jest.Mocked<Logger> = getLoggerFor('AbacUtil') as any;
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

  const definitions = parse(`
    ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ;
      abac:value ex:None, ex:Doctor ; abac:defaultValue ex:None .
    ex:department a abac:AttributeDefinition ; abac:appliesTo abac:Subject ;
      abac:value ex:Unknown, ex:Cardiology, ex:Emergency, ex:Oncology ; abac:defaultValue ex:Unknown .
    ex:category a abac:AttributeDefinition ; abac:appliesTo abac:Resource ;
      abac:value ex:Any, ex:Medical ; abac:defaultValue ex:Any .
    ex:unscoped a abac:AttributeDefinition ; abac:value ex:Any ; abac:defaultValue ex:Any .
    ex:misscoped a abac:AttributeDefinition ; abac:appliesTo abac:Subjects ;
      abac:value ex:Any ; abac:defaultValue ex:Any .
    ex:undefaulted a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:value ex:Any .
    ex:ambiguous a abac:AttributeDefinition ; abac:appliesTo abac:Subject ;
      abac:value ex:A, ex:B ; abac:defaultValue ex:A, ex:B .
    ex:unvalued a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:Any .
    ex:outside a abac:AttributeDefinition ; abac:appliesTo abac:Subject ;
      abac:value ex:A, ex:B ; abac:defaultValue ex:Any .
  `);
  const defined = [ ...getAttributeDefinitions(definitions) ];

  const rules = parse(`
    <#R001> a abac:Rule ;
      abac:grants acl:Read, acl:Write ;
      abac:allOf  [ a ex:Condition ; ex:role ex:Doctor ; ex:status ex:Active ] ;
      abac:anyOf  [ ex:department ex:Cardiology, ex:Emergency ] ;
      abac:noneOf [ ex:status ex:Suspended ] .
    <#R002> a abac:Rule ; abac:grants acl:Read .
  `);

  beforeEach((): void => {
    jest.clearAllMocks();
  });

  describe('#getAttributeDefinitions', (): void => {
    it('returns every definition with one known kind of entity and one default in its values.', (): void => {
      function definition(name: string, appliesTo: string, values: string[]): AttributeDefinition {
        return {
          iri: `${ex}${name}`,
          appliesTo,
          values: new Set(values.map((value): string => `${ex}${value}`)),
          defaultValue: `${ex}${values[0]}`,
        };
      }
      expect([ ...getAttributeDefinitions(definitions) ]).toEqual([
        definition('role', ABAC.Subject, [ 'None', 'Doctor' ]),
        definition('department', ABAC.Subject, [ 'Unknown', 'Cardiology', 'Emergency', 'Oncology' ]),
        definition('category', ABAC.Resource, [ 'Any', 'Medical' ]),
      ]);
      expect(logger.warn).toHaveBeenCalledTimes(6);
      expect(logger.warn).toHaveBeenLastCalledWith(expect.stringContaining(
        `Skipping attribute definition ${ex}outside`,
      ));
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
    const records = `${baseUrl}records/`;
    const note = `${records}2026/note.ttl`;
    const entities = [ note, `${records}2026/`, records, baseUrl ].map((entity): NamedNode => namedNode(entity));

    it('uses the assigned value where there is one, the default otherwise.', (): void => {
      const assignments = parse(`<${alice}> ex:role ex:Doctor ; ex:clearance ex:High .`);
      expect(buildAttributeVector(defined, assignments, [ namedNode(alice) ])).toEqual({
        [`${ex}role`]: `${ex}Doctor`,
        [`${ex}department`]: `${ex}Unknown`,
        [`${ex}category`]: `${ex}Any`,
      });
    });

    it('resolves every attribute for an entity that was never assigned anything.', (): void => {
      expect(buildAttributeVector(defined, new Store(), [ namedNode(alice) ])).toEqual({
        [`${ex}role`]: `${ex}None`,
        [`${ex}department`]: `${ex}Unknown`,
        [`${ex}category`]: `${ex}Any`,
      });
    });

    it('takes each value from the most specific entity that assigns it.', (): void => {
      const assignments = parse(`
        <${records}> ex:category ex:Medical ; ex:department ex:Cardiology .
        <${note}> ex:department ex:Emergency .
      `);
      expect(buildAttributeVector(defined, assignments, entities)).toEqual({
        [`${ex}role`]: `${ex}None`,
        [`${ex}department`]: `${ex}Emergency`,
        [`${ex}category`]: `${ex}Medical`,
      });
    });

    it('leaves out an attribute assigned several values, or a value outside its space.', (): void => {
      const assignments = parse(`
        <${records}> ex:department ex:Cardiology ; ex:category ex:Surgical .
        <${note}> ex:department ex:Emergency, ex:Oncology .
      `);
      expect(buildAttributeVector(defined, assignments, entities)).toEqual({
        [`${ex}role`]: `${ex}None`,
      });
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining(`${note} assigns ${ex}department several values`),
      );
      expect(logger.warn).toHaveBeenCalledWith(
        `${records} assigns ${ex}category ${ex}Surgical, which is not one of its values`,
      );
    });
  });

  describe('#getMirroredResource', (): void => {
    it('returns the resource that a part of the resources subtree mirrors, by host and path.', (): void => {
      const resources = `${baseUrl}.abac/resources/`;
      expect(getMirroredResource(`${resources}example.com/records/`, resources)).toBe(`${baseUrl}records/`);
      const local = 'http://localhost:3000/.abac/resources/';
      expect(getMirroredResource(`${local}alice.localhost/notes`, local)).toBe('http://alice.localhost:3000/notes');
      expect(getMirroredResource(`${local}localhost`, local)).toBe('http://localhost:3000');
      expect(getMirroredResource(resources, resources)).toBeUndefined();
      expect(getMirroredResource(`${baseUrl}.abac/rules/R001`, resources)).toBeUndefined();
    });
  });

  describe('#isWithin', (): void => {
    it('accepts the scope itself and what lies beneath it, at a path boundary.', (): void => {
      const records = `${baseUrl}records`;
      expect([ records, `${records}/`, `${records}/2026/note.ttl` ].map((path): boolean => isWithin(path, records)))
        .toEqual([ true, true, true ]);
      expect([ `${records}-2026/`, baseUrl ].map((path): boolean => isWithin(path, records))).toEqual([ false, false ]);
    });
  });

  describe('#buildEnvironmentVector', (): void => {
    it('uses the resolved value where there is one in the space, the default otherwise.', (): void => {
      const resolved = { [`${ex}role`]: `${ex}Doctor`, [`${ex}category`]: `${ex}Elsewhere` };
      expect(buildEnvironmentVector(defined, resolved)).toEqual({
        [`${ex}role`]: `${ex}Doctor`,
        [`${ex}department`]: `${ex}Unknown`,
      });
      expect(logger.warn).toHaveBeenCalledWith(
        `The request has ${ex}category ${ex}Elsewhere, which is not one of its values`,
      );
    });
  });
});

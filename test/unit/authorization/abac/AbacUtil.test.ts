import type { NamedNode } from '@rdfjs/types';
import { DataFactory, Parser, Store } from 'n3';
import {
  buildAttributeVector,
  buildEnvironmentVector,
  getAttributeDefinitions,
  getRules,
} from '../../../../src/authorization/abac/AbacUtil';
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
    ex:role a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:None .
    ex:department a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:Unknown .
    ex:category a abac:AttributeDefinition ; abac:appliesTo abac:Resource ; abac:defaultValue ex:Any .
    ex:unscoped a abac:AttributeDefinition ; abac:defaultValue ex:Any .
    ex:misscoped a abac:AttributeDefinition ; abac:appliesTo abac:Subjects ; abac:defaultValue ex:Any .
    ex:undefaulted a abac:AttributeDefinition ; abac:appliesTo abac:Subject .
    ex:ambiguous a abac:AttributeDefinition ; abac:appliesTo abac:Subject ; abac:defaultValue ex:A, ex:B .
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
    it('returns every definition with one known kind of entity and one default.', (): void => {
      expect([ ...getAttributeDefinitions(definitions) ]).toEqual([
        { iri: `${ex}role`, appliesTo: ABAC.Subject, defaultValue: `${ex}None` },
        { iri: `${ex}department`, appliesTo: ABAC.Subject, defaultValue: `${ex}Unknown` },
        { iri: `${ex}category`, appliesTo: ABAC.Resource, defaultValue: `${ex}Any` },
      ]);
      expect(logger.warn).toHaveBeenCalledTimes(4);
      expect(logger.warn).toHaveBeenLastCalledWith(expect.stringContaining(
        `Skipping attribute definition ${ex}ambiguous`,
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

    it('leaves out an attribute that is assigned several values.', (): void => {
      const assignments = parse(`
        <${records}> ex:department ex:Cardiology .
        <${note}> ex:department ex:Emergency, ex:Oncology .
      `);
      expect(buildAttributeVector(defined, assignments, entities)).toEqual({
        [`${ex}role`]: `${ex}None`,
        [`${ex}category`]: `${ex}Any`,
      });
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining(`${note} assigns ${ex}department several values`),
      );
    });
  });

  describe('#buildEnvironmentVector', (): void => {
    it('uses the resolved value where there is one, the default otherwise.', (): void => {
      expect(buildEnvironmentVector(defined, { [`${ex}role`]: `${ex}Doctor` })).toEqual({
        [`${ex}role`]: `${ex}Doctor`,
        [`${ex}department`]: `${ex}Unknown`,
        [`${ex}category`]: `${ex}Any`,
      });
    });
  });
});

import { DataFactory } from 'n3';
import type { Store } from 'n3';
import type { NamedNode, Term } from '@rdfjs/types';
import { getLoggerFor } from '../../logging/LogUtil';
import { ABAC, RDF } from '../../util/Vocabularies';
import type { AttributeCondition, AttributeDefinition, AttributeVector, Rule } from './AbacTypes';

const logger = getLoggerFor('AbacUtil');

const entityKinds: ReadonlySet<string> = new Set([ ABAC.Subject, ABAC.Resource, ABAC.Environment ]);

/**
 * Returns the string values of all objects found using the given subject and predicate.
 */
function getObjectValues(data: Store, subject: Term, predicate: NamedNode): string[] {
  return data.getObjects(subject, predicate, null).map((term): string => term.value);
}

/**
 * Finds all {@link AttributeDefinition} in the given dataset.
 * A definition needs a single `appliesTo` naming the kind of entity it describes,
 * its value space as one or more `value`s, and a single `defaultValue` among them.
 * Any other is skipped with a warning: it is unclear what it describes, what values it takes,
 * or what an unassigned entity resolves to.
 *
 * @param data - Dataset to look in.
 */
export function* getAttributeDefinitions(data: Store): Iterable<AttributeDefinition> {
  for (const quad of data.getQuads(null, RDF.terms.type, ABAC.terms.AttributeDefinition, null)) {
    const appliesTo = getObjectValues(data, quad.subject, ABAC.terms.appliesTo);
    const values = getObjectValues(data, quad.subject, ABAC.terms.value);
    const defaultValue = getObjectValues(data, quad.subject, ABAC.terms.defaultValue);
    if (appliesTo.length !== 1 || !entityKinds.has(appliesTo[0]) ||
      defaultValue.length !== 1 || !values.includes(defaultValue[0])) {
      logger.warn(`Skipping attribute definition ${quad.subject.value}, which needs one abac:appliesTo ` +
        `naming a Subject, Resource or Environment, and one abac:defaultValue among its abac:value list. ` +
        `Found appliesTo [${appliesTo.join(', ')}], defaultValue [${defaultValue.join(', ')}] ` +
        `and value [${values.join(', ')}].`);
      continue;
    }
    yield { iri: quad.subject.value, appliesTo: appliesTo[0], values: new Set(values), defaultValue: defaultValue[0] };
  }
}

/**
 * Converts a condition node such as `[ ex:role ex:Doctor ]` into one {@link AttributeCondition}
 * per predicate, ignoring `rdf:type`.
 */
function getConditions(data: Store, node: Term): AttributeCondition[] {
  const byAttribute = new Map<string, string[]>();
  for (const quad of data.getQuads(node, null, null, null)) {
    if (quad.predicate.equals(RDF.terms.type)) {
      continue;
    }
    const values = byAttribute.get(quad.predicate.value) ?? [];
    values.push(quad.object.value);
    byAttribute.set(quad.predicate.value, values);
  }
  return [ ...byAttribute ].map(([ attribute, values ]): AttributeCondition => ({ attribute, values }));
}

/**
 * Returns all conditions attached to the given rule through the given predicate.
 */
function getConditionList(data: Store, rule: Term, predicate: NamedNode): AttributeCondition[] {
  return data.getObjects(rule, predicate, null).flatMap((node): AttributeCondition[] => getConditions(data, node));
}

/**
 * Finds all {@link Rule}s in the given dataset.
 *
 * @param data - Dataset to look in.
 */
export function* getRules(data: Store): Iterable<Rule> {
  for (const quad of data.getQuads(null, RDF.terms.type, ABAC.terms.Rule, null)) {
    yield {
      iri: quad.subject.value,
      grants: new Set(getObjectValues(data, quad.subject, ABAC.terms.grants)),
      allOf: getConditionList(data, quad.subject, ABAC.terms.allOf),
      anyOf: getConditionList(data, quad.subject, ABAC.terms.anyOf),
      noneOf: getConditionList(data, quad.subject, ABAC.terms.noneOf),
    };
  }
}

/**
 * Builds the attribute vector of an entity, taking each value from the first of the given entities
 * that assigns it, and falling back to each definition's default.
 * If that entity assigns an attribute several values, or one outside its value space,
 * the attribute is left out with a warning, so no rule naming it matches:
 * attributes are single-valued, and picking one would be arbitrary.
 *
 * @param definitions - Definitions of every attribute the vector should cover.
 * @param assignments - Dataset holding the assignments, keyed by the entity as RDF subject.
 * @param entities - The entity followed by those it inherits values from, most specific first.
 */
export function buildAttributeVector(
  definitions: Iterable<AttributeDefinition>,
  assignments: Store,
  entities: NamedNode[],
): AttributeVector {
  const vector: AttributeVector = {};
  for (const definition of definitions) {
    const attribute = DataFactory.namedNode(definition.iri);
    const entity = entities.find((candidate): boolean => assignments.countQuads(candidate, attribute, null, null) > 0);
    const values = entity ? getObjectValues(assignments, entity, attribute) : [ definition.defaultValue ];
    if (values.length > 1) {
      logger.warn(`${entity!.value} assigns ${definition.iri} several values, so none applies: ${values.join(', ')}`);
      continue;
    }
    if (!definition.values.has(values[0])) {
      logger.warn(`${entity!.value} assigns ${definition.iri} ${values[0]}, which is not one of its values`);
      continue;
    }
    vector[definition.iri] = values[0];
  }
  return vector;
}

/**
 * Builds the attribute vector of the request environment,
 * taking each value from those derived from the request and falling back to each definition's default.
 * A derived value outside the attribute's value space leaves the attribute out, with a warning.
 *
 * @param definitions - Definitions of every attribute the vector should cover.
 * @param resolved - Values derived from the request, which need not cover every definition.
 */
export function buildEnvironmentVector(
  definitions: Iterable<AttributeDefinition>,
  resolved: AttributeVector,
): AttributeVector {
  const vector: AttributeVector = {};
  for (const definition of definitions) {
    const value = resolved[definition.iri] ?? definition.defaultValue;
    if (!definition.values.has(value)) {
      logger.warn(`The request has ${definition.iri} ${value}, which is not one of its values`);
      continue;
    }
    vector[definition.iri] = value;
  }
  return vector;
}

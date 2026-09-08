import { DataFactory } from 'n3';
import type { Store } from 'n3';
import type { NamedNode, Term } from '@rdfjs/types';
import { ABAC, RDF } from '../../util/Vocabularies';
import type { AttributeCondition, AttributeDefinition, AttributeVector, Rule } from './AbacTypes';

/**
 * Returns the string values of all objects found using the given subject and predicate.
 */
function getObjectValues(data: Store, subject: Term, predicate: NamedNode): string[] {
  return data.getObjects(subject, predicate, null).map((term): string => term.value);
}

/**
 * Returns the string value of the first object found using the given subject and predicate.
 */
function getObjectValue(data: Store, subject: Term, predicate: NamedNode): string | undefined {
  return getObjectValues(data, subject, predicate)[0];
}

/**
 * Finds all {@link AttributeDefinition} in the given dataset, skipping any without a `defaultValue`.
 *
 * @param data - Dataset to look in.
 */
export function* getAttributeDefinitions(data: Store): Iterable<AttributeDefinition> {
  for (const quad of data.getQuads(null, RDF.terms.type, ABAC.terms.AttributeDefinition, null)) {
    const defaultValue = getObjectValue(data, quad.subject, ABAC.terms.defaultValue);
    if (!defaultValue) {
      continue;
    }
    yield {
      iri: quad.subject.value,
      appliesTo: getObjectValue(data, quad.subject, ABAC.terms.appliesTo) ?? ABAC.Subject,
      defaultValue,
    };
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
 * Builds the attribute vector for the given subject, falling back to each definition's default.
 *
 * @param definitions - Definitions of every attribute the vector should cover.
 * @param assignments - Dataset holding the assignments, keyed by the entity as RDF subject.
 * @param subject - Entity to build the vector for.
 */
export function buildAttributeVector(
  definitions: Iterable<AttributeDefinition>,
  assignments: Store,
  subject: NamedNode,
): AttributeVector {
  const vector: AttributeVector = {};
  for (const definition of definitions) {
    const assigned = assignments.getObjects(subject, DataFactory.namedNode(definition.iri), null)[0];
    vector[definition.iri] = assigned?.value ?? definition.defaultValue;
  }
  return vector;
}

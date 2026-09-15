/**
 * The definition of a single attribute, as found in the `/.abac/definitions/` subtree.
 * `appliesTo` is the kind of entity it describes, a subject or a resource.
 */
export interface AttributeDefinition {
  iri: string;
  appliesTo: string;
  defaultValue: string;
}

/**
 * A condition inside a rule, satisfied when the attribute has any of the listed values.
 */
export interface AttributeCondition {
  attribute: string;
  values: string[];
}

/**
 * A rule from the global catalogue: the ACL modes it grants when its conditions hold.
 * `allOf` requires every condition, `anyOf` at least one, and `noneOf` none.
 */
export interface Rule {
  iri: string;
  grants: Set<string>;
  allOf: AttributeCondition[];
  anyOf: AttributeCondition[];
  noneOf: AttributeCondition[];
}

/**
 * Every defined attribute IRI mapped to its resolved value.
 */
export type AttributeVector = Record<string, string>;

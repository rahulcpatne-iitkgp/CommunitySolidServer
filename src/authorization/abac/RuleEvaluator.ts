import type { AttributeCondition, AttributeVector, Rule } from './AbacTypes';

/**
 * Whether the vector's value for the condition's attribute is one of the listed values.
 */
function satisfies(condition: AttributeCondition, vector: AttributeVector): boolean {
  return condition.values.includes(vector[condition.attribute]);
}

/**
 * Whether the vector has a value for the condition's attribute.
 */
function isValued(condition: AttributeCondition, vector: AttributeVector): boolean {
  return typeof vector[condition.attribute] === 'string';
}

/**
 * Whether the rule's conditions hold for the given attribute vector.
 * A rule without any conditions never matches, so an empty rule cannot grant everything.
 * Neither does a rule with a condition on an attribute the vector has no value for,
 * so a `noneOf` condition naming an undefined attribute cannot hold for everyone.
 */
function matches(rule: Rule, vector: AttributeVector): boolean {
  const conditions = [ ...rule.allOf, ...rule.anyOf, ...rule.noneOf ];
  if (conditions.length === 0 || !conditions.every((condition): boolean => isValued(condition, vector))) {
    return false;
  }
  return rule.allOf.every((condition): boolean => satisfies(condition, vector)) &&
    (rule.anyOf.length === 0 || rule.anyOf.some((condition): boolean => satisfies(condition, vector))) &&
    !rule.noneOf.some((condition): boolean => satisfies(condition, vector));
}

/**
 * Returns the union of the ACL modes granted by every rule matching the given attribute vector.
 *
 * @param rules - Rules of the global catalogue.
 * @param vector - Attribute vector to evaluate them against.
 */
export function evaluateRules(rules: Iterable<Rule>, vector: AttributeVector): Set<string> {
  const granted = new Set<string>();
  for (const rule of rules) {
    if (matches(rule, vector)) {
      for (const mode of rule.grants) {
        granted.add(mode);
      }
    }
  }
  return granted;
}

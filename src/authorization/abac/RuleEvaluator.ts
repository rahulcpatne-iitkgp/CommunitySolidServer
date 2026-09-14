import type { AttributeCondition, AttributeVector, Rule } from './AbacTypes';

/**
 * Whether the vector's value for the condition's attribute is one of the listed values.
 */
function satisfies(condition: AttributeCondition, vector: AttributeVector): boolean {
  const value = vector[condition.attribute];
  return typeof value === 'string' && condition.values.includes(value);
}

/**
 * Whether the rule's conditions hold for the given attribute vector.
 * A rule without any conditions never matches, so an empty rule cannot grant everything.
 */
function matches(rule: Rule, vector: AttributeVector): boolean {
  if (rule.allOf.length + rule.anyOf.length + rule.noneOf.length === 0) {
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

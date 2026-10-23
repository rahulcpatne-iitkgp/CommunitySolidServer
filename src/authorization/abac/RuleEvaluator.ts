import type { AttributeMatcher } from '../PolicyEvaluator';
import { evaluatePolicy } from '../PolicyEvaluator';
import type { AttributeCondition, AttributeVector, Rule } from './AbacTypes';

function toMatcher(condition: AttributeCondition): AttributeMatcher {
  return { iri: condition.attribute, agent: [], client: [], issuer: [], vc: [], attributes: [ condition ]};
}

/** Returns the union of ACL modes granted by definitely matching catalogue rules. */
export function evaluateRules(rules: Iterable<Rule>, vector: AttributeVector): Set<string> {
  const granted = new Set<string>();
  for (const rule of rules) {
    const conditions = [ ...rule.allOf, ...rule.anyOf, ...rule.noneOf ];
    // Keep the catalogue's stricter rule: every condition must have a value, including alternatives.
    if (conditions.some(({ attribute }): boolean => typeof vector[attribute] !== 'string')) {
      continue;
    }
    const policy = {
      allOf: rule.allOf.map(toMatcher),
      anyOf: rule.anyOf.map(toMatcher),
      noneOf: rule.noneOf.map(toMatcher),
    };
    if (evaluatePolicy(policy, { target: '' }, vector).definite) {
      for (const mode of rule.grants) {
        granted.add(mode);
      }
    }
  }
  return granted;
}

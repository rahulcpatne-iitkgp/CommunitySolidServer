import type { IContext, IMatcher, IPolicy } from '@solid/access-control-policy';
import { matchAgent, matchClient, matchIssuer } from '@solid/access-control-policy';
import type { AttributeCondition, AttributeDefinition, AttributeVector } from './abac/AbacTypes';

/** Custom predicates in an ACP matcher use the same value space as catalogue conditions. */
export type AttributeMatcher = IMatcher & { attributes?: AttributeCondition[] };

type MatchResult = 'yes' | 'no' | 'unknown';

function all(results: MatchResult[]): MatchResult {
  if (results.includes('no')) {
    return 'no';
  }
  return results.includes('unknown') ? 'unknown' : 'yes';
}

function any(results: MatchResult[]): MatchResult {
  if (results.includes('yes')) {
    return 'yes';
  }
  return results.includes('unknown') ? 'unknown' : 'no';
}

function negate(result: MatchResult): MatchResult {
  if (result === 'yes') {
    return 'no';
  }
  return result === 'no' ? 'yes' : 'unknown';
}

/**
 * A missing or invalid attribute is unknown, rather than false. In particular, treating it as false
 * inside `noneOf` would enable an allow or suppress a denial.
 */
function matchAttribute(
  { attribute, values }: AttributeCondition,
  vector: AttributeVector,
  definitions?: ReadonlyMap<string, AttributeDefinition>,
): MatchResult {
  const definition = definitions?.get(attribute);
  if ((definitions && (!definition || values.some((value): boolean => !definition.values.has(value)))) ||
    typeof vector[attribute] !== 'string') {
    return 'unknown';
  }
  return values.includes(vector[attribute]) ? 'yes' : 'no';
}

/** A matcher's predicates are conjunctive; values of one predicate are alternatives. */
export function matchPolicyMatcher(
  matcher: AttributeMatcher,
  context: IContext,
  vector: AttributeVector,
  definitions?: ReadonlyMap<string, AttributeDefinition>,
): MatchResult {
  const results: MatchResult[] = [];
  for (const [ values, matches ] of [
    [ matcher.agent, matchAgent ],
    [ matcher.client, matchClient ],
    [ matcher.issuer, matchIssuer ],
    [ matcher.vc, (candidate: IMatcher, current: IContext): boolean =>
      Boolean(current.vc?.some((vc): boolean => candidate.vc.includes(vc))) ],
  ] as const) {
    if (values.length > 0) {
      results.push(matches(matcher, context) ? 'yes' : 'no');
    }
  }
  for (const condition of matcher.attributes ?? []) {
    results.push(matchAttribute(condition, vector, definitions));
  }
  return results.length === 0 ? 'no' : all(results);
}

/**
 * Evaluates ACP's allOf/anyOf/noneOf policy shape for both owner policies and catalogue rules.
 * A possible match is used for denials; only a definite match can allow access.
 */
export function evaluatePolicy(
  policy: Pick<IPolicy, 'allOf' | 'anyOf' | 'noneOf'>,
  context: IContext,
  vector: AttributeVector,
  definitions?: ReadonlyMap<string, AttributeDefinition>,
): { definite: boolean; possible: boolean } {
  if (policy.allOf.length + policy.anyOf.length === 0) {
    return { definite: false, possible: false };
  }
  function evaluate(matcher: IMatcher): MatchResult {
    return matchPolicyMatcher(matcher as AttributeMatcher, context, vector, definitions);
  }
  const result = all([
    all(policy.allOf.map(evaluate)),
    policy.anyOf.length === 0 ? 'yes' : any(policy.anyOf.map(evaluate)),
    negate(any(policy.noneOf.map(evaluate))),
  ]);
  return { definite: result === 'yes', possible: result !== 'no' };
}

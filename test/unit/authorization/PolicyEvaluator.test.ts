import type { IContext, IMatcher, IPolicy } from '@solid/access-control-policy';
import { ACP, applyPolicy } from '@solid/access-control-policy';
import type { AttributeDefinition, AttributeVector } from '../../../src/authorization/abac/AbacTypes';
import type { AttributeMatcher } from '../../../src/authorization/PolicyEvaluator';
import { evaluatePolicy, matchPolicyMatcher } from '../../../src/authorization/PolicyEvaluator';
import { ACL } from '../../../src/util/Vocabularies';

const role = 'http://example.org/role';
const doctor = 'http://example.org/Doctor';
const nurse = 'http://example.org/Nurse';
const alice = 'http://example.org/alice#me';
const empty: IMatcher = { iri: 'empty', agent: [], client: [], issuer: [], vc: []};
const definitions = new Map<string, AttributeDefinition>([[ role, {
  iri: role,
  appliesTo: 'https://w3id.org/solid-abac#Subject',
  values: new Set([ doctor, nurse ]),
  defaultValue: nurse,
}]]);
const context: IContext = { target: 'http://example.org/data', agent: alice };

function matcher(attribute = role, values = [ doctor ], agent: string[] = []): AttributeMatcher {
  return { ...empty, agent, attributes: [{ attribute, values }]};
}

function policy(allOf: IMatcher[] = [], anyOf: IMatcher[] = [], noneOf: IMatcher[] = []): IPolicy {
  return { iri: 'policy', allow: new Set([ ACL.Read ]), deny: new Set(), allOf, anyOf, noneOf };
}

describe('The shared policy evaluator', (): void => {
  it('preserves the library result for the supported built-in ACP matchers.', (): void => {
    const builtIns: IMatcher[] = [
      { ...empty, agent: [ alice ]},
      { ...empty, agent: [ ACP.PublicAgent ]},
      { ...empty, agent: [ ACP.AuthenticatedAgent ]},
      { ...empty, agent: [ ACP.OwnerAgent ]},
      { ...empty, agent: [ ACP.CreatorAgent ]},
      { ...empty, client: [ ACP.PublicClient ]},
      { ...empty, client: [ 'http://example.org/client' ]},
      { ...empty, issuer: [ 'http://example.org/issuer' ]},
      { ...empty, vc: [ 'http://example.org/credential' ]},
      empty,
    ];
    for (const candidate of builtIns) {
      for (const current of [ context, {
        ...context,
        client: 'http://example.org/client',
        issuer: 'http://example.org/issuer',
        vc: [ 'http://example.org/credential' ],
        owner: [ alice ],
        creator: [ alice ],
      }]) {
        const applied = policy([ candidate ]);
        expect(evaluatePolicy(applied, current, {}).definite).toBe(applyPolicy(applied, current));
      }
    }
  });

  it('conjoins identity and attribute predicates while treating values as alternatives.', (): void => {
    const mixed = matcher(role, [ nurse, doctor ], [ alice ]);
    expect(matchPolicyMatcher(mixed, context, { [role]: doctor }, definitions)).toBe('yes');
    expect(matchPolicyMatcher(mixed, { ...context, agent: 'bob' }, { [role]: doctor }, definitions)).toBe('no');
    expect(matchPolicyMatcher(mixed, context, { [role]: 'other' }, definitions)).toBe('no');
    expect(matchPolicyMatcher(empty, context, {}, definitions)).toBe('no');
  });

  it('uses the same allOf, anyOf and noneOf rules for owner and catalogue policies.', (): void => {
    const yes = matcher();
    const no = matcher(role, [ nurse ]);
    expect(evaluatePolicy(policy([ yes ], [ no, yes ], [ no ]), context, { [role]: doctor }, definitions))
      .toEqual({ definite: true, possible: true });
    expect(evaluatePolicy(policy([ yes ], [ no ], []), context, { [role]: doctor }, definitions))
      .toEqual({ definite: false, possible: false });
    expect(evaluatePolicy(policy([], [], [ no ]), context, { [role]: doctor }, definitions))
      .toEqual({ definite: false, possible: false });
  });

  it('never lets an unknown or invalid attribute establish an allow or suppress a possible denial.', (): void => {
    for (const invalid of [ matcher('http://example.org/unknown'), matcher(role, [ 'outside' ]), matcher() ]) {
      const vector: AttributeVector = invalid.attributes?.[0].attribute === role &&
        invalid.attributes[0].values[0] === doctor ?
          {} :
          { [role]: doctor };
      expect(matchPolicyMatcher(invalid, context, vector, definitions)).toBe('unknown');
      expect(evaluatePolicy(policy([ invalid ]), context, vector, definitions))
        .toEqual({ definite: false, possible: true });
      const publicExceptInvalid = policy([{ ...empty, agent: [ ACP.PublicAgent ]}], [], [ invalid ]);
      expect(evaluatePolicy(publicExceptInvalid, context, vector, definitions))
        .toEqual({ definite: false, possible: true });
    }
  });

  it('does not apply a possible denial when another required predicate definitely fails.', (): void => {
    expect(evaluatePolicy(policy([ matcher(role, [ doctor ], [ 'bob' ]) ]), context, {}, definitions))
      .toEqual({ definite: false, possible: false });
  });
});

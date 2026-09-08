import type { AttributeCondition, AttributeVector, Rule } from '../../../../src/authorization/abac/AbacTypes';
import { evaluateRules } from '../../../../src/authorization/abac/RuleEvaluator';

describe('A RuleEvaluator', (): void => {
  const ex = 'http://example.org/hospital#';
  const acl = 'http://www.w3.org/ns/auth/acl#';

  function condition(attribute: string, ...values: string[]): AttributeCondition {
    return { attribute: `${ex}${attribute}`, values: values.map((value): string => `${ex}${value}`) };
  }

  function rule(iri: string, grants: string[], conditions: Partial<Rule> = {}): Rule {
    return { iri, grants: new Set(grants), allOf: [], anyOf: [], noneOf: [], ...conditions };
  }

  const vector: AttributeVector = {
    [`${ex}role`]: `${ex}Doctor`,
    [`${ex}department`]: `${ex}Cardiology`,
    [`${ex}status`]: `${ex}Active`,
  };

  // Three rules match and three do not, one per way of failing: allOf, anyOf and noneOf.
  const rules = [
    rule(`${ex}R001`, [ `${acl}Read` ], { allOf: [ condition('role', 'Doctor') ]}),
    rule(`${ex}R002`, [ `${acl}Write` ], { allOf: [ condition('role', 'Nurse') ]}),
    rule(`${ex}R003`, [ `${acl}Control` ], { anyOf: [ condition('department', 'Cardiology', 'Emergency') ]}),
    rule(`${ex}R004`, [ `${acl}Write` ], { anyOf: [ condition('role', 'Nurse', 'Porter') ]}),
    rule(`${ex}R005`, [ `${acl}Append` ], {
      allOf: [ condition('role', 'Doctor') ],
      noneOf: [ condition('status', 'Suspended') ],
    }),
    rule(`${ex}R006`, [ `${acl}Write` ], {
      allOf: [ condition('role', 'Doctor') ],
      noneOf: [ condition('status', 'Active') ],
    }),
  ];

  const granted = new Set([ `${acl}Read`, `${acl}Control`, `${acl}Append` ]);

  it('grants the union of the modes of every matching rule.', (): void => {
    expect(evaluateRules(rules, vector)).toEqual(granted);
  });

  it('grants nothing for an empty catalogue.', (): void => {
    expect(evaluateRules([], vector)).toEqual(new Set());
  });

  it('does not match a rule that declares no conditions.', (): void => {
    expect(evaluateRules([ rule(`${ex}R007`, [ `${acl}Read` ]) ], vector)).toEqual(new Set());
  });

  it('does not satisfy a condition on an attribute the vector does not cover.', (): void => {
    const unknown = [ rule(`${ex}R008`, [ `${acl}Read` ], { allOf: [ condition('clearance', 'High') ]}) ];
    expect(evaluateRules(unknown, vector)).toEqual(new Set());
  });

  it('reaches the same result whatever order the rules are evaluated in.', (): void => {
    const permutations = [
      [ ...rules ].reverse(),
      [ ...rules.slice(3), ...rules.slice(0, 3) ],
      [ ...rules.slice(1), rules[0] ],
    ];
    for (const permutation of permutations) {
      expect(evaluateRules(permutation, vector)).toEqual(granted);
    }
  });
});

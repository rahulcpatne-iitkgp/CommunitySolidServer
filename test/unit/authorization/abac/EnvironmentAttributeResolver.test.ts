import type { RequestEnvironment } from '../../../../src/authentication/EnvironmentCredentialsExtractor';
import type { AttributeVector } from '../../../../src/authorization/abac/AbacTypes';
import { EnvironmentAttributeResolver } from '../../../../src/authorization/abac/EnvironmentAttributeResolver';
import { ABAC } from '../../../../src/util/Vocabularies';

type Facts = {
  time?: string;
  date?: string;
  ip?: string;
  authScheme?: RequestEnvironment['authScheme'];
};

describe('An EnvironmentAttributeResolver', (): void => {
  const resolver = new EnvironmentAttributeResolver('09:00', '17:00', [ '^127\\.', '^::1$' ]);

  // A Wednesday, the Saturday that follows it, and the Sunday after that.
  const workday = '2026-10-07';
  const saturday = '2026-10-10';
  const sunday = '2026-10-11';

  function resolve({ time = '12:00', date = workday, ...rest }: Facts): AttributeVector {
    return resolver.resolve({ timestamp: new Date(`${date}T${time}:00`), ...rest });
  }

  it('decides the period by the configured window.', (): void => {
    expect(resolve({ time: '09:00' })).toMatchObject({ [ABAC.period]: ABAC.BusinessHours });
    expect(resolve({ time: '16:59' })).toMatchObject({ [ABAC.period]: ABAC.BusinessHours });
    expect(resolve({ time: '08:59' })).toMatchObject({ [ABAC.period]: ABAC.OutOfHours });
    expect(resolve({ time: '17:00' })).toMatchObject({ [ABAC.period]: ABAC.OutOfHours });
    expect(resolve({ time: '22:00' })).toMatchObject({ [ABAC.period]: ABAC.OutOfHours });
  });

  it('supports a window that crosses midnight.', (): void => {
    const nightly = new EnvironmentAttributeResolver('22:00', '06:00', []);

    function at(time: string): string {
      return nightly.resolve({ timestamp: new Date(`${workday}T${time}:00`) })[ABAC.period];
    }

    expect(at('23:30')).toBe(ABAC.BusinessHours);
    expect(at('05:59')).toBe(ABAC.BusinessHours);
    expect(at('12:00')).toBe(ABAC.OutOfHours);
  });

  it('splits the week into workdays and the weekend.', (): void => {
    expect(resolve({ date: workday })).toMatchObject({ [ABAC.dayType]: ABAC.Workday });
    expect(resolve({ date: saturday })).toMatchObject({ [ABAC.dayType]: ABAC.Weekend });
    expect(resolve({ date: sunday })).toMatchObject({ [ABAC.dayType]: ABAC.Weekend });
  });

  it('decides the network by the configured addresses.', (): void => {
    expect(resolve({ ip: '127.0.0.1' })).toMatchObject({ [ABAC.network]: ABAC.Internal });
    expect(resolve({ ip: '::1' })).toMatchObject({ [ABAC.network]: ABAC.Internal });
    expect(resolve({ ip: '10.145.123.160' })).toMatchObject({ [ABAC.network]: ABAC.External });
  });

  it('leaves out an attribute whose fact the request does not supply.', (): void => {
    expect(resolve({})).not.toHaveProperty(ABAC.network);
  });

  it('reports how the identity was proven.', (): void => {
    expect(resolve({ authScheme: 'DPoP' })).toMatchObject({ [ABAC.authMethod]: ABAC.BoundToken });
    expect(resolve({ authScheme: 'Bearer' })).toMatchObject({ [ABAC.authMethod]: ABAC.BearerToken });
    expect(resolve({ authScheme: 'WebID' })).toMatchObject({ [ABAC.authMethod]: ABAC.Unsecure });
    expect(resolve({})).toMatchObject({ [ABAC.authMethod]: ABAC.NoCredentials });
  });

  it('rejects a window it cannot parse.', (): void => {
    expect((): unknown => new EnvironmentAttributeResolver('9am', '17:00', []))
      .toThrow('Invalid time of day 9am, expected HH:MM.');
    expect((): unknown => new EnvironmentAttributeResolver('09:00', '24:00', [])).toThrow('Invalid time of day 24:00');
    expect((): unknown => new EnvironmentAttributeResolver('09:60', '17:00', [])).toThrow('Invalid time of day 09:60');
  });
});

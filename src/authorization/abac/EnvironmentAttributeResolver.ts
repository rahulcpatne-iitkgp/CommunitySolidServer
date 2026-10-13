import type { RequestEnvironment } from '../../authentication/EnvironmentCredentialsExtractor';
import { ABAC } from '../../util/Vocabularies';
import type { AttributeVector } from './AbacTypes';

const authMethods = new Map<RequestEnvironment['authScheme'], string>([
  [ 'DPoP', ABAC.BoundToken ],
  [ 'Bearer', ABAC.BearerToken ],
  [ 'WebID', ABAC.Unsecure ],
]);

/**
 * Parses an `HH:MM` time of day into minutes since midnight.
 */
function toMinutes(time: string): number {
  const match = /^([01]\d|2[0-3]):([0-5]\d)$/u.exec(time);
  if (!match) {
    throw new Error(`Invalid time of day ${time}, expected HH:MM.`);
  }
  return Number(match[1]) * 60 + Number(match[2]);
}

/**
 * Derives the environment attributes of {@link ABAC} from the circumstances of a request.
 *
 * Unlike subject and resource attributes these are never assigned, so they carry no entity and no store document.
 * Their IRIs and values belong to the vocabulary rather than to a deployment, because the server computes them:
 * a deployment configures what they mean here, but cannot rename them and so cannot silently mistype one.
 */
export class EnvironmentAttributeResolver {
  private readonly windowStart: number;
  private readonly windowEnd: number;
  private readonly internalNetworks: RegExp[];

  /**
   * @param businessHoursStart - Start of the business-hours window, as `HH:MM` in the server's time zone.
   * @param businessHoursEnd - End of that window, exclusive. A value below the start makes the window cross midnight.
   * @param internalNetworks - Regular expressions matching the addresses that count as the internal network.
   */
  public constructor(businessHoursStart: string, businessHoursEnd: string, internalNetworks: string[]) {
    this.windowStart = toMinutes(businessHoursStart);
    this.windowEnd = toMinutes(businessHoursEnd);
    this.internalNetworks = internalNetworks.map((network): RegExp => new RegExp(network, 'u'));
  }

  /**
   * The value of every environment attribute the given request supplies the facts for.
   * An attribute is left out when its fact is missing, so the definition's default applies instead.
   */
  public resolve({ timestamp, ip, authScheme }: RequestEnvironment): AttributeVector {
    const vector: AttributeVector = {
      [ABAC.period]: this.inWindow(timestamp) ? ABAC.BusinessHours : ABAC.OutOfHours,
      [ABAC.dayType]: this.isWorkday(timestamp) ? ABAC.Workday : ABAC.Weekend,
      [ABAC.authMethod]: authMethods.get(authScheme) ?? ABAC.NoCredentials,
    };
    if (typeof ip === 'string') {
      vector[ABAC.network] = this.internalNetworks.some((network): boolean => network.test(ip)) ?
        ABAC.Internal :
        ABAC.External;
    }
    return vector;
  }

  private inWindow(timestamp: Date): boolean {
    const minutes = timestamp.getHours() * 60 + timestamp.getMinutes();
    return this.windowStart <= this.windowEnd ?
      minutes >= this.windowStart && minutes < this.windowEnd :
      minutes >= this.windowStart || minutes < this.windowEnd;
  }

  private isWorkday(timestamp: Date): boolean {
    const day = timestamp.getDay();
    return day >= 1 && day <= 5;
  }
}

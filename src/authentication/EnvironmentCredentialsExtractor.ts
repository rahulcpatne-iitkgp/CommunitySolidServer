import type { HttpRequest } from '../server/HttpRequest';
import { matchesAuthorizationScheme } from '../util/HeaderUtil';
import type { Credentials } from './Credentials';
import { CredentialsExtractor } from './CredentialsExtractor';

const schemes = [ 'DPoP', 'Bearer', 'WebID' ] as const;

/**
 * The circumstances of a request, as opposed to the identity it claims.
 */
export interface RequestEnvironment {
  /** When the request was received. */
  timestamp: Date;
  /** Address the request was received from, absent if the connection does not report one. */
  ip?: string;
  /** Authorization scheme the request used, absent if it sent no recognised credentials. */
  authScheme?: typeof schemes[number];
}

/**
 * Records the circumstances of a request in `credentials.environment`,
 * so authorization can take them into account.
 *
 * Deliberately records facts rather than conclusions, and verifies nothing:
 * the schemes have their own extractors, which is where a claimed WebID is proven.
 * A scheme recorded here is therefore only what the request claimed,
 * safe to act on only alongside a WebID one of those extractors established.
 */
export class EnvironmentCredentialsExtractor extends CredentialsExtractor {
  public async handle(request: HttpRequest): Promise<Credentials> {
    const environment: RequestEnvironment = {
      timestamp: new Date(),
      // Behind a reverse proxy this is the proxy's address. `X-Forwarded-For` holds the client's,
      // but is client-settable and only trustworthy if the proxy overwrites it, so it is not used here.
      ip: request.socket.remoteAddress,
      authScheme: schemes.find((scheme): boolean => matchesAuthorizationScheme(scheme, request.headers.authorization)),
    };
    return { environment };
  }
}

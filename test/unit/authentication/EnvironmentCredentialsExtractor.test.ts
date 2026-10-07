import { EnvironmentCredentialsExtractor } from '../../../src/authentication/EnvironmentCredentialsExtractor';
import type { RequestEnvironment } from '../../../src/authentication/EnvironmentCredentialsExtractor';
import type { HttpRequest } from '../../../src/server/HttpRequest';

describe('An EnvironmentCredentialsExtractor', (): void => {
  const extractor = new EnvironmentCredentialsExtractor();

  async function extract(authorization?: string, remoteAddress?: string): Promise<RequestEnvironment> {
    const request = { headers: authorization ? { authorization } : {}, socket: { remoteAddress }} as HttpRequest;
    const { environment } = await extractor.handleSafe(request);
    return environment as RequestEnvironment;
  }

  it('records the scheme the request claimed, whatever its case.', async(): Promise<void> => {
    await expect(extract('DPoP token')).resolves.toMatchObject({ authScheme: 'DPoP' });
    await expect(extract('bearer token')).resolves.toMatchObject({ authScheme: 'Bearer' });
    await expect(extract('WebID http://example.com/alice#me')).resolves.toMatchObject({ authScheme: 'WebID' });
  });

  it('records no scheme for a request without recognised credentials.', async(): Promise<void> => {
    await expect(extract()).resolves.toMatchObject({ authScheme: undefined });
    await expect(extract('Other token')).resolves.toMatchObject({ authScheme: undefined });
  });

  it('records the address the request arrived from, if the connection reports one.', async(): Promise<void> => {
    await expect(extract(undefined, '127.0.0.1')).resolves.toMatchObject({ ip: '127.0.0.1' });
    await expect(extract()).resolves.toMatchObject({ ip: undefined });
  });

  it('records when the request was received.', async(): Promise<void> => {
    const before = Date.now();
    const { timestamp } = await extract();
    expect(timestamp.getTime()).toBeGreaterThanOrEqual(before);
    expect(timestamp.getTime()).toBeLessThanOrEqual(Date.now());
  });
});

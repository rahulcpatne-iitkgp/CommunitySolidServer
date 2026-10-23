import { Readable } from 'node:stream';
import type { IAccessControlledResource, IContext, IPolicy } from '@solid/access-control-policy';
import { applyPolicy } from '@solid/access-control-policy';
import type { Store } from 'n3';
import type { Credentials } from '../authentication/Credentials';
import type { AuxiliaryStrategy } from '../http/auxiliary/AuxiliaryStrategy';
import type { ResourceIdentifier } from '../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../logging/LogUtil';
import type { ResourceStore } from '../storage/ResourceStore';
import { INTERNAL_QUADS } from '../util/ContentTypes';
import { createErrorMessage } from '../util/errors/ErrorUtil';
import { InternalServerError } from '../util/errors/InternalServerError';
import { NotFoundHttpError } from '../util/errors/NotFoundHttpError';
import type { IdentifierStrategy } from '../util/identifiers/IdentifierStrategy';
import { IdentifierMap, IdentifierSetMultiMap } from '../util/map/IdentifierMap';
import { getDefault } from '../util/map/MapUtil';
import { readableToQuads } from '../util/StreamUtil';
import { ACL } from '../util/Vocabularies';
import { getAccessControlledResources } from './AcpUtil';
import type { AbacRequestContext } from './abac/AbacContextBuilder';
import type { AbacGrantReader } from './abac/AbacGrantReader';
import type { GrantMap, GrantReader } from './GrantReader';
import type { AttributeMatcher } from './PolicyEvaluator';
import { evaluatePolicy } from './PolicyEvaluator';
import type { PermissionReaderInput } from './PermissionReader';
import { PermissionReader } from './PermissionReader';
import type { AclPermissionSet } from './permissions/AclPermissionSet';
import { AclMode } from './permissions/AclPermissionSet';
import { AccessMode } from './permissions/Permissions';
import type { PermissionMap, PermissionSet } from './permissions/Permissions';

const modesMap: Record<string, readonly (keyof AclPermissionSet)[]> = {
  [ACL.Read]: [ AccessMode.read ],
  [ACL.Write]: [ AccessMode.append, AccessMode.write ],
  [ACL.Append]: [ AccessMode.append ],
  [ACL.Control]: [ AclMode.control ],
} as const;

// Access granted outside the ACRs counts only for these modes.
const grantableModes: ReadonlySet<string> = new Set([ ACL.Read, ACL.Write, ACL.Append ]);

/**
 * Finds the permissions of a resource as defined in the corresponding ACRs.
 * Implementation based on https://solid.github.io/authorization-panel/acp-specification/.
 *
 * Access granted outside the ACRs, by an optional {@link GrantReader}, is evaluated as one more allow
 * beside their policies, so a policy that denies a mode overrides it as it would any other allow.
 * An optional {@link AbacGrantReader} also shares its resolved attribute context with ACP matchers.
 * Such access never includes Control: that is control over the ACRs themselves,
 * which would let it rewrite the very policies that override it.
 *
 * Caches data so no duplicate calls are made to the {@link ResourceStore} for a single request.
 */
export class AcpReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly acrStrategy: AuxiliaryStrategy;
  private readonly acrStore: ResourceStore;
  private readonly identifierStrategy: IdentifierStrategy;
  private readonly grantReader?: GrantReader;
  private readonly abacReader?: AbacGrantReader;

  public constructor(
    acrStrategy: AuxiliaryStrategy,
    acrStore: ResourceStore,
    identifierStrategy: IdentifierStrategy,
    grantReader?: GrantReader,
    abacReader?: AbacGrantReader,
  ) {
    super();
    this.acrStrategy = acrStrategy;
    this.acrStore = acrStore;
    this.identifierStrategy = identifierStrategy;
    this.grantReader = grantReader;
    this.abacReader = abacReader;
  }

  public async handle({ credentials, requestedModes }: PermissionReaderInput): Promise<PermissionMap> {
    this.logger.debug(`Retrieving permissions of ${JSON.stringify(credentials)}`);
    const resourceCache = new IdentifierMap<IAccessControlledResource[]>();
    const policiesByTarget = new IdentifierMap<IPolicy[]>();
    const permissionMap: PermissionMap = new IdentifierMap();

    // Resolves the targets sequentially so the `resourceCache` can be filled and reused
    for (const target of requestedModes.distinctKeys()) {
      policiesByTarget.set(target, await this.getPolicies(target, resourceCache));
    }

    let abac: Awaited<ReturnType<AbacGrantReader['prepare']>> | undefined;
    if (this.abacReader) {
      try {
        abac = await this.abacReader.prepare({ credentials, requestedModes });
      } catch (error: unknown) {
        const hasAttributePolicy = [ ...policiesByTarget.values() ].some((policies): boolean =>
          policies.some((policy): boolean => [ ...policy.allOf, ...policy.anyOf, ...policy.noneOf ]
            .some((matcher): boolean => Boolean((matcher as AttributeMatcher).attributes?.length))));
        if (hasAttributePolicy) {
          throw new InternalServerError(`Cannot evaluate owner attribute policies: ${createErrorMessage(error)}`, {
            cause: error,
          });
        }
        this.logger.warn(
          `Ignoring organisational grants whose attributes could not be read: ${createErrorMessage(error)}`,
        );
      }
    }
    const grants = await this.readGrants({ credentials, requestedModes });
    for (const target of requestedModes.distinctKeys()) {
      const granted = new Set([ ...grants.get(target) ?? [], ...abac?.grants.get(target) ?? [] ]);
      permissionMap.set(target, this.extractPermissions(
        target,
        credentials,
        policiesByTarget.get(target)!,
        granted,
        abac?.context,
      ));
    }
    return permissionMap;
  }

  /**
   * Finds the access granted outside the ACRs.
   * It can only add to what the ACRs allow, so a failure to determine it is logged
   * rather than taking away what they allow.
   */
  private async readGrants(input: PermissionReaderInput): Promise<GrantMap> {
    if (!this.grantReader) {
      return new IdentifierSetMultiMap();
    }
    try {
      return await this.grantReader.handleSafe(input);
    } catch (error: unknown) {
      this.logger.warn(
        `Ignoring access granted outside the ACRs, which could not be determined: ${createErrorMessage(error)}`,
      );
      return new IdentifierSetMultiMap();
    }
  }

  /**
   * Generates the allowed permissions.
   *
   * @param target - Target to generate permissions for.
   * @param credentials - Credentials that are trying to access the resource.
   * @param policies - Effective policies from the target and its ancestors.
   * @param granted - Access modes granted on the target outside the ACRs.
   */
  private extractPermissions(
    target: ResourceIdentifier,
    credentials: Credentials,
    policies: IPolicy[],
    granted: ReadonlySet<string>,
    abac?: AbacRequestContext,
  ): PermissionSet {
    const context = this.createContext(target, credentials);

    const denied = new Set<string>();
    const ownerAllowed = new Set<string>();
    for (const policy of policies) {
      const result = abac ? evaluatePolicy(policy, context, abac.vectors.get(target)!, abac.definitions) : undefined;
      const applies = result ? undefined : applyPolicy(policy, context);
      const { definite, possible } = result ?? { definite: applies, possible: applies };
      if (definite) {
        for (const mode of policy.allow) {
          ownerAllowed.add(mode);
        }
      }
      if (possible) {
        for (const mode of policy.deny) {
          denied.add(mode);
        }
      }
    }
    // The catalogue is consulted only where the owner's policies are silent on that ACL mode.
    const grants = [ ...granted ].filter((mode): boolean => grantableModes.has(mode) &&
      !ownerAllowed.has(mode) && !denied.has(mode));
    const allowed = [ ...ownerAllowed, ...grants ];
    const overridden = [ ...granted ].filter((mode): boolean => denied.has(mode));
    if (overridden.length > 0) {
      this.logger.debug(
        `ACP denies ${overridden.join(', ')} on ${target.path}, overriding access granted outside the ACRs`,
      );
    }

    const permissionSet: PermissionSet = {};
    for (const aclMode of allowed) {
      if (aclMode in modesMap && !denied.has(aclMode)) {
        for (const mode of modesMap[aclMode]) {
          permissionSet[mode as AccessMode] = true;
        }
      }
    }
    return permissionSet;
  }

  /** Extracts the effective policies once per target, reusing each ancestor's parsed ACR. */
  private async getPolicies(
    target: ResourceIdentifier,
    resourceCache: IdentifierMap<IAccessControlledResource[]>,
  ): Promise<IPolicy[]> {
    const policies: IPolicy[] = [];
    for (const identifier of this.getAncestorIdentifiers(target)) {
      const acrs = await getDefault(resourceCache, identifier, async(): Promise<IAccessControlledResource[]> =>
        [ ...getAccessControlledResources(await this.readAcrData(identifier)) ]);
      const size = policies.length;
      policies.push(...this.getEffectivePolicies(target, acrs));
      this.logger.debug(`Found ${policies.length - size} policies relevant for ${target.path} in ${identifier.path}`);
    }
    return policies;
  }

  /**
   * Creates an ACP context targeting the given identifier with the provided credentials.
   */
  private createContext(target: ResourceIdentifier, credentials: Credentials): IContext {
    return {
      target: target.path,
      agent: credentials.agent?.webId,
      client: credentials.client?.clientId,
      issuer: credentials.issuer?.url,
    };
  }

  /**
   * Returns all {@link IPolicy} found in `resources` that apply to the target identifier.
   * https://solidproject.org/TR/2022/acp-20220518#effective-policies
   */
  private* getEffectivePolicies(target: ResourceIdentifier, resources: Iterable<IAccessControlledResource>):
  Iterable<IPolicy> {
    for (const { iri, accessControlResource } of resources) {
      // Use the `accessControl` entries if the `target` corresponds to the `iri` used in the ACR.
      // If not, this means this is an ACR of a parent resource, and we need to use the `memberAccessControl` field.
      const accessControlField = iri === target.path ? 'accessControl' : 'memberAccessControl';
      yield* accessControlResource[accessControlField].flatMap((ac): IPolicy[] => ac.policy);
    }
  }

  /**
   * Returns the given identifier and all its ancestors.
   * These are all the identifiers that are relevant for determining the effective policies.
   */
  private* getAncestorIdentifiers(identifier: ResourceIdentifier): Iterable<ResourceIdentifier> {
    yield identifier;
    while (!this.identifierStrategy.isRootContainer(identifier)) {
      identifier = this.identifierStrategy.getParentContainer(identifier);
      yield identifier;
    }
  }

  /**
   * Returns the data found in the ACR corresponding to the given identifier.
   */
  private async readAcrData(identifier: ResourceIdentifier): Promise<Store> {
    const acrIdentifier = this.acrStrategy.getAuxiliaryIdentifier(identifier);
    let data: Readable;
    try {
      this.logger.debug(`Reading ACR document ${acrIdentifier.path}`);
      ({ data } = await this.acrStore.getRepresentation(acrIdentifier, { type: { [INTERNAL_QUADS]: 1 }}));
    } catch (error: unknown) {
      if (!NotFoundHttpError.isInstance(error)) {
        const message = `Error reading ACR ${acrIdentifier.path}: ${createErrorMessage(error)}`;
        this.logger.error(message);
        throw new InternalServerError(message, { cause: error });
      }
      this.logger.debug(`No direct ACR document found for ${identifier.path}`);
      data = Readable.from([]);
    }
    return readableToQuads(data);
  }
}

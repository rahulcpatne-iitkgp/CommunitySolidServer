import { AsyncHandler } from '../util/handlers/AsyncHandler';
import type { IdentifierSetMultiMap } from '../util/map/IdentifierMap';
import type { PermissionReaderInput } from './PermissionReader';

/**
 * The allowed modes on each resource, as ACL mode IRIs such as `acl:Read`.
 */
export type AllowedModesMap = IdentifierSetMultiMap<string>;

/**
 * Determines which ACL modes an external source allows outside the resource's ACR.
 * It cannot deny access. An `AcpReader` applies owner denials before these modes
 * and ignores outside Control so they cannot rewrite the owner's policy.
 */
export abstract class AllowedModesReader extends AsyncHandler<PermissionReaderInput, AllowedModesMap> {}

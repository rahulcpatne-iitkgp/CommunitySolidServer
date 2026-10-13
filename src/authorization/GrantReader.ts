import { AsyncHandler } from '../util/handlers/AsyncHandler';
import type { IdentifierSetMultiMap } from '../util/map/IdentifierMap';
import type { PermissionReaderInput } from './PermissionReader';

/**
 * The access modes granted on each resource, as the IRIs an ACP policy allows, such as `acl:Read`.
 */
export type GrantMap = IdentifierSetMultiMap<string>;

/**
 * Determines which access modes are granted on resources from outside their access control resources.
 * It can only grant, never deny: an `AcpReader` evaluates the grants as one more allow,
 * so a policy denying a mode still overrides them, and it ignores any grant of Control,
 * which would let the grant rewrite that policy.
 */
export abstract class GrantReader extends AsyncHandler<PermissionReaderInput, GrantMap> {}

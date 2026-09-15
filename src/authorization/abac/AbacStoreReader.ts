import { IdentifierMap } from '../../util/map/IdentifierMap';
import { joinUrl } from '../../util/PathUtil';
import type { PermissionReaderInput } from '../PermissionReader';
import { PermissionReader } from '../PermissionReader';
import type { PermissionMap, PermissionSet } from '../permissions/Permissions';

const adminPermissions: PermissionSet = Object.freeze({
  read: true,
  append: true,
  write: true,
  create: true,
  delete: true,
});
const publicPermissions: PermissionSet = Object.freeze({
  read: true,
  append: false,
  write: false,
  create: false,
  delete: false,
});
const noPermissions: PermissionSet = Object.freeze({
  read: false,
  append: false,
  write: false,
  create: false,
  delete: false,
});

/**
 * Determines access to the ABAC store: only the administrator may write it,
 * while anyone may read the attribute definitions and rules.
 *
 * Unlike `AbacPermissionReader` it returns explicit `false`, as only that overrides what other readers grant.
 */
export class AbacStoreReader extends PermissionReader {
  private readonly admin: string;
  private readonly publicContainers: string[];

  /**
   * @param baseUrl - Base URL of the server.
   * @param admin - WebID of the ABAC administrator.
   * @param container - Path of the ABAC store relative to the base URL.
   */
  public constructor(baseUrl: string, admin: string, container = '.abac/') {
    super();
    this.admin = admin;
    const root = joinUrl(baseUrl, container);
    this.publicContainers = [ joinUrl(root, 'definitions/'), joinUrl(root, 'rules/') ];
  }

  public async handle({ credentials, requestedModes }: PermissionReaderInput): Promise<PermissionMap> {
    const isAdmin = credentials.agent?.webId === this.admin;
    const result: PermissionMap = new IdentifierMap();
    for (const target of requestedModes.distinctKeys()) {
      result.set(target, isAdmin ? adminPermissions : this.getPublicPermissions(target.path));
    }
    return result;
  }

  /**
   * Read access inside the public containers, nothing anywhere else.
   */
  private getPublicPermissions(path: string): PermissionSet {
    const isPublic = this.publicContainers.some((container): boolean => path.startsWith(container));
    return isPublic ? publicPermissions : noPermissions;
  }
}

import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import type { PodStore } from '../../identity/interaction/pod/util/PodStore';
import { getLoggerFor } from '../../logging/LogUtil';
import type { StorageLocationStrategy } from '../../server/description/StorageLocationStrategy';
import { IdentifierMap } from '../../util/map/IdentifierMap';
import { ensureTrailingSlash, joinUrl } from '../../util/PathUtil';
import type { PermissionReaderInput } from '../PermissionReader';
import { PermissionReader } from '../PermissionReader';
import type { PermissionMap, PermissionSet } from '../permissions/Permissions';
import { getMirroredResource } from './AbacUtil';

const adminPermissions: PermissionSet = Object.freeze({
  read: true,
  append: true,
  write: true,
  create: true,
  delete: true,
});
const readPermissions: PermissionSet = Object.freeze({
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
 * while anyone may read the attribute definitions and rules,
 * and a pod owner the part of the resource assignments that mirrors their pod.
 *
 * That part can only label resources in the pod, since a document there assigns attributes
 * to nothing but what it mirrors and what lies beneath it, and pods do not nest.
 * A part mirroring something above every pod, such as the root container, has no owner.
 *
 * Unlike `AbacGrantReader`, which can only grant, it returns explicit `false`,
 * as only that overrides what other readers grant.
 */
export class AbacStoreReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly admin: string;
  private readonly podStore: PodStore;
  private readonly storageStrategy: StorageLocationStrategy;
  private readonly publicContainers: string[];
  private readonly resourcesContainer: string;

  /**
   * @param baseUrl - Base URL of the server.
   * @param admin - WebID of the ABAC administrator.
   * @param podStore - Used to find the owners of a pod.
   * @param storageStrategy - Used to find the pod a resource is in.
   * @param container - Path of the ABAC store relative to the base URL.
   */
  public constructor(
    baseUrl: string,
    admin: string,
    podStore: PodStore,
    storageStrategy: StorageLocationStrategy,
    container = '.abac/',
  ) {
    super();
    this.admin = admin;
    this.podStore = podStore;
    this.storageStrategy = storageStrategy;
    const root = joinUrl(baseUrl, container);
    this.publicContainers = [ joinUrl(root, 'definitions/'), joinUrl(root, 'rules/') ];
    this.resourcesContainer = joinUrl(root, 'resources/');
  }

  public async handle({ credentials, requestedModes }: PermissionReaderInput): Promise<PermissionMap> {
    const webId = credentials.agent?.webId;
    const result: PermissionMap = new IdentifierMap();
    for (const target of requestedModes.distinctKeys()) {
      result.set(target, await this.getPermissions(target, webId));
    }
    return result;
  }

  private async getPermissions(target: ResourceIdentifier, webId?: string): Promise<PermissionSet> {
    if (webId === this.admin) {
      return adminPermissions;
    }
    if (this.publicContainers.some((container): boolean => target.path.startsWith(container))) {
      return readPermissions;
    }
    if (webId && await this.ownsMirroredPod(target, webId)) {
      return readPermissions;
    }
    return noPermissions;
  }

  /**
   * Whether the target mirrors a resource in a pod the agent owns.
   * The pod is found from that resource as a container, which holds everything the target can label.
   */
  private async ownsMirroredPod(target: ResourceIdentifier, webId: string): Promise<boolean> {
    const mirrored = getMirroredResource(target.path, this.resourcesContainer);
    if (!mirrored) {
      return false;
    }
    let storage: ResourceIdentifier;
    try {
      storage = await this.storageStrategy.getStorageIdentifier({ path: ensureTrailingSlash(mirrored) });
    } catch {
      this.logger.debug(`${target.path} mirrors ${mirrored}, which is in no pod`);
      return false;
    }
    const pod = await this.podStore.findByBaseUrl(storage.path);
    const owners = pod ? await this.podStore.getOwners(pod.id) : undefined;
    return Boolean(owners?.some((owner): boolean => owner.webId === webId));
  }
}

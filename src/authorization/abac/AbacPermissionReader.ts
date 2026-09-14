import { DataFactory } from 'n3';
import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../../logging/LogUtil';
import { IdentifierMap } from '../../util/map/IdentifierMap';
import { ensureTrailingSlash, trimTrailingSlashes } from '../../util/PathUtil';
import { ACL } from '../../util/Vocabularies';
import type { PermissionReaderInput } from '../PermissionReader';
import { PermissionReader } from '../PermissionReader';
import type { AclPermissionSet } from '../permissions/AclPermissionSet';
import { AclMode } from '../permissions/AclPermissionSet';
import { AccessMode } from '../permissions/Permissions';
import type { PermissionMap } from '../permissions/Permissions';
import type { AbacDataLoader } from './AbacDataLoader';
import { buildAttributeVector, getAttributeDefinitions, getRules } from './AbacUtil';
import { evaluateRules } from './RuleEvaluator';

const modesMap: Record<string, readonly (keyof AclPermissionSet)[]> = {
  [ACL.Read]: [ AccessMode.read ],
  [ACL.Write]: [ AccessMode.append, AccessMode.write ],
  [ACL.Append]: [ AccessMode.append ],
  [ACL.Control]: [ AclMode.control ],
} as const;

/**
 * Grants access based on the requesting agent's attributes in the ABAC store,
 * matched against the rules of the global catalogue.
 *
 * Never returns `false`, only `true` or nothing, so it can add access on top of WAC/ACP but never remove any.
 */
export class AbacPermissionReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly loader: AbacDataLoader;
  private readonly baseUrl: string;
  private readonly excludePaths: RegExp[];

  /**
   * @param loader - Used to read the ABAC store.
   * @param baseUrl - Base URL of the server.
   * @param excludePaths - Regular expressions, relative to the base URL and starting with a slash,
   *                       of resources this reader never grants access to.
   */
  public constructor(loader: AbacDataLoader, baseUrl: string, excludePaths: string[]) {
    super();
    this.loader = loader;
    this.baseUrl = ensureTrailingSlash(baseUrl);
    this.excludePaths = excludePaths.map((path): RegExp => new RegExp(path, 'u'));
  }

  public async handle({ credentials, requestedModes }: PermissionReaderInput): Promise<PermissionMap> {
    const result: PermissionMap = new IdentifierMap();

    const webId = credentials.agent?.webId;
    if (!webId) {
      this.logger.debug(`No WebID found, ABAC has no opinion on this request.`);
      return result;
    }

    const modes = await this.findGrantedModes(webId);
    if (modes.size === 0) {
      return result;
    }

    const permissions = this.toPermissionSet(modes);
    // Rules have no resource conditions yet, so every target gets the same permissions
    for (const target of requestedModes.distinctKeys()) {
      if (this.isExcluded(target)) {
        this.logger.debug(`ABAC will not grant anything on the excluded resource ${target.path}`);
        continue;
      }
      result.set(target, permissions);
    }
    return result;
  }

  /**
   * Whether the given identifier is outside the server or matches one of the excluded paths.
   * The `PathBasedReader` veto does not cover `/.internal/` here, as `AuxiliaryReader` has already
   * rewritten that identifier to its subject resource.
   */
  private isExcluded(identifier: ResourceIdentifier): boolean {
    if (!identifier.path.startsWith(this.baseUrl) && `${identifier.path}/` !== this.baseUrl) {
      return true;
    }
    const relative = identifier.path.slice(trimTrailingSlashes(this.baseUrl).length);
    return this.excludePaths.some((regex): boolean => regex.test(relative));
  }

  /**
   * Builds the attribute vector for the given agent and returns every ACL mode the catalogue grants it.
   */
  private async findGrantedModes(webId: string): Promise<Set<string>> {
    const [ definitionData, assignmentData, ruleData ] = await Promise.all([
      this.loader.readDefinitions(),
      this.loader.readSubjectAttributes(),
      this.loader.readRules(),
    ]);

    const vector = buildAttributeVector(
      getAttributeDefinitions(definitionData),
      assignmentData,
      DataFactory.namedNode(webId),
    );
    const modes = evaluateRules(getRules(ruleData), vector);

    this.logger.debug(`ABAC vector for ${webId}: ${JSON.stringify(vector)} grants [${[ ...modes ].join(', ')}]`);
    return modes;
  }

  /**
   * Converts granted ACL modes into a permission set, leaving every other mode absent rather than `false`.
   */
  private toPermissionSet(modes: Set<string>): AclPermissionSet {
    const permissions: AclPermissionSet = {};
    for (const mode of modes) {
      for (const permission of modesMap[mode] ?? []) {
        permissions[permission] = true;
      }
    }
    return permissions;
  }
}

import type { NamedNode } from '@rdfjs/types';
import { DataFactory } from 'n3';
import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../../logging/LogUtil';
import type { IdentifierStrategy } from '../../util/identifiers/IdentifierStrategy';
import { IdentifierMap } from '../../util/map/IdentifierMap';
import { ensureTrailingSlash, trimTrailingSlashes } from '../../util/PathUtil';
import { ABAC, ACL } from '../../util/Vocabularies';
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
 * Grants access based on the attributes of the requesting agent and of each target resource in the ABAC store,
 * matched against the rules of the global catalogue.
 * A resource inherits the attribute values of its closest ancestor that assigns them.
 *
 * Never returns `false`, only `true` or nothing, so it can add access on top of WAC/ACP but never remove any.
 */
export class AbacPermissionReader extends PermissionReader {
  protected readonly logger = getLoggerFor(this);

  private readonly loader: AbacDataLoader;
  private readonly identifierStrategy: IdentifierStrategy;
  private readonly baseUrl: string;
  private readonly excludePaths: RegExp[];

  /**
   * @param loader - Used to read the ABAC store.
   * @param identifierStrategy - Used to find the ancestors a resource inherits attribute values from.
   * @param baseUrl - Base URL of the server.
   * @param excludePaths - Regular expressions, relative to the base URL and starting with a slash,
   *                       of resources this reader never grants access to.
   */
  public constructor(
    loader: AbacDataLoader,
    identifierStrategy: IdentifierStrategy,
    baseUrl: string,
    excludePaths: string[],
  ) {
    super();
    this.loader = loader;
    this.identifierStrategy = identifierStrategy;
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

    const [ definitionData, subjectData, resourceData, ruleData ] = await Promise.all([
      this.loader.readDefinitions(),
      this.loader.readSubjectAttributes(),
      this.loader.readResourceAttributes(),
      this.loader.readRules(),
    ]);
    const definitions = [ ...getAttributeDefinitions(definitionData) ];
    const resourceDefinitions = definitions.filter(({ appliesTo }): boolean => appliesTo === ABAC.Resource);
    const subjectVector = buildAttributeVector(
      definitions.filter(({ appliesTo }): boolean => appliesTo === ABAC.Subject),
      subjectData,
      [ DataFactory.namedNode(webId) ],
    );
    const rules = [ ...getRules(ruleData) ];

    for (const target of requestedModes.distinctKeys()) {
      if (this.isExcluded(target)) {
        this.logger.debug(`ABAC will not grant anything on the excluded resource ${target.path}`);
        continue;
      }
      const vector = {
        ...subjectVector,
        ...buildAttributeVector(resourceDefinitions, resourceData, this.getAncestors(target)),
      };
      const modes = evaluateRules(rules, vector);
      this.logger.debug(
        `ABAC grants ${webId} [${[ ...modes ].join(', ')}] on ${target.path}: ${JSON.stringify(vector)}`,
      );
      if (modes.size > 0) {
        result.set(target, this.toPermissionSet(modes));
      }
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
   * The given resource followed by all its ancestors, most specific first.
   * Only paths are compared, so a resource that does not exist yet resolves against its would-be ancestors.
   */
  private getAncestors(identifier: ResourceIdentifier): NamedNode[] {
    const ancestors = [ DataFactory.namedNode(identifier.path) ];
    while (!this.identifierStrategy.isRootContainer(identifier)) {
      identifier = this.identifierStrategy.getParentContainer(identifier);
      ancestors.push(DataFactory.namedNode(identifier.path));
    }
    return ancestors;
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

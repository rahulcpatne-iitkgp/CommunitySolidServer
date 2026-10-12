import type { NamedNode } from '@rdfjs/types';
import { DataFactory } from 'n3';
import type { RequestEnvironment } from '../../authentication/EnvironmentCredentialsExtractor';
import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../../logging/LogUtil';
import type { IdentifierStrategy } from '../../util/identifiers/IdentifierStrategy';
import { IdentifierSetMultiMap } from '../../util/map/IdentifierMap';
import { ensureTrailingSlash, trimTrailingSlashes } from '../../util/PathUtil';
import { ABAC } from '../../util/Vocabularies';
import type { GrantMap } from '../GrantReader';
import { GrantReader } from '../GrantReader';
import type { PermissionReaderInput } from '../PermissionReader';
import type { AbacDataLoader } from './AbacDataLoader';
import type { AttributeDefinition, AttributeVector } from './AbacTypes';
import { buildAttributeVector, buildEnvironmentVector, getAttributeDefinitions, getRules } from './AbacUtil';
import type { EnvironmentAttributeResolver } from './EnvironmentAttributeResolver';
import { evaluateRules } from './RuleEvaluator';

/**
 * Determines which access modes the rules of the global catalogue grant on each target,
 * based on the attributes of the requesting agent, of the target in the ABAC store,
 * and of the circumstances of the request.
 * A resource inherits the attribute values of its closest ancestor that assigns them.
 */
export class AbacGrantReader extends GrantReader {
  protected readonly logger = getLoggerFor(this);

  private readonly loader: AbacDataLoader;
  private readonly identifierStrategy: IdentifierStrategy;
  private readonly environmentResolver: EnvironmentAttributeResolver;
  private readonly baseUrl: string;
  private readonly excludePaths: RegExp[];

  /**
   * @param loader - Used to read the ABAC store.
   * @param identifierStrategy - Used to find the ancestors a resource inherits attribute values from.
   * @param environmentResolver - Used to value the attributes describing the request itself.
   * @param baseUrl - Base URL of the server.
   * @param excludePaths - Regular expressions, relative to the base URL and starting with a slash,
   *                       of resources this reader never grants access to.
   */
  public constructor(
    loader: AbacDataLoader,
    identifierStrategy: IdentifierStrategy,
    environmentResolver: EnvironmentAttributeResolver,
    baseUrl: string,
    excludePaths: string[],
  ) {
    super();
    this.loader = loader;
    this.identifierStrategy = identifierStrategy;
    this.environmentResolver = environmentResolver;
    this.baseUrl = ensureTrailingSlash(baseUrl);
    this.excludePaths = excludePaths.map((path): RegExp => new RegExp(path, 'u'));
  }

  public async handle({ credentials, requestedModes }: PermissionReaderInput): Promise<GrantMap> {
    const result: GrantMap = new IdentifierSetMultiMap();

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
    const environmentVector = this.resolveEnvironment(
      definitions.filter(({ appliesTo }): boolean => appliesTo === ABAC.Environment),
      credentials.environment as RequestEnvironment | undefined,
    );
    const rules = [ ...getRules(ruleData) ];

    for (const target of requestedModes.distinctKeys()) {
      if (this.isExcluded(target)) {
        this.logger.debug(`ABAC will not grant anything on the excluded resource ${target.path}`);
        continue;
      }
      const vector = {
        ...subjectVector,
        ...environmentVector,
        ...buildAttributeVector(resourceDefinitions, resourceData, this.getAncestors(target)),
      };
      const modes = evaluateRules(rules, vector);
      this.logger.debug(
        `ABAC grants ${webId} [${[ ...modes ].join(', ')}] on ${target.path}: ${JSON.stringify(vector)}`,
      );
      result.set(target, modes);
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
   * Values the environment attributes against the circumstances of the request.
   * Falls back to their declared defaults when nothing recorded those circumstances,
   * which means the extractor that records them is missing from the configuration.
   */
  private resolveEnvironment(definitions: AttributeDefinition[], environment?: RequestEnvironment): AttributeVector {
    if (definitions.length === 0) {
      return {};
    }
    if (!environment) {
      this.logger.warn(`No request context was recorded, so environment attributes fall back to their defaults.`);
    }
    return buildEnvironmentVector(definitions, environment ? this.environmentResolver.resolve(environment) : {});
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
}

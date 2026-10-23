import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../../logging/LogUtil';
import { createErrorMessage } from '../../util/errors/ErrorUtil';
import type { IdentifierStrategy } from '../../util/identifiers/IdentifierStrategy';
import { IdentifierSetMultiMap } from '../../util/map/IdentifierMap';
import { ensureTrailingSlash, trimTrailingSlashes } from '../../util/PathUtil';
import { ABAC } from '../../util/Vocabularies';
import type { AllowedModesMap } from '../AllowedModesReader';
import { AllowedModesReader } from '../AllowedModesReader';
import type { PermissionReaderInput } from '../PermissionReader';
import type { AbacDataLoader } from './AbacDataLoader';
import type { AbacRequestContext } from './AbacContextBuilder';
import { AbacContextBuilder } from './AbacContextBuilder';
import type { AttributeCondition, AttributeDefinition, Rule } from './AbacTypes';
import { getRules } from './AbacUtil';
import type { EnvironmentAttributeResolver } from './EnvironmentAttributeResolver';
import { evaluateRules } from './RuleEvaluator';

/**
 * Whether the condition is on an attribute of the resource, given the definition of every attribute it can name.
 */
function isOnResource({ attribute }: AttributeCondition, defined: Map<string, AttributeDefinition>): boolean {
  return defined.get(attribute)!.appliesTo === ABAC.Resource;
}

/**
 * Determines which access modes the rules of the global catalogue allow on each target,
 * based on the attributes of the requesting agent, of the target in the ABAC store,
 * and of the circumstances of the request.
 * A resource inherits the attribute values of its closest ancestor that assigns them.
 * Every rule has to condition on the resource, so the catalogue only opens what has been labelled.
 */
export class AbacAllowedModesReader extends AllowedModesReader {
  protected readonly logger = getLoggerFor(this);

  private readonly loader: AbacDataLoader;
  private readonly identifierStrategy: IdentifierStrategy;
  private readonly contextBuilder: AbacContextBuilder;
  private readonly baseUrl: string;
  private readonly excludePaths: RegExp[];

  /**
   * @param loader - Used to read the ABAC store.
   * @param identifierStrategy - Used to find the ancestors a resource inherits attribute values from.
   * @param environmentResolver - Used to value the attributes describing the request itself.
   * @param baseUrl - Base URL of the server.
   * @param excludePaths - Regular expressions, relative to the base URL and starting with a slash,
   *                       of resources this reader never allows access to.
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
    this.contextBuilder = new AbacContextBuilder(loader, identifierStrategy, environmentResolver);
    this.baseUrl = ensureTrailingSlash(baseUrl);
    this.excludePaths = excludePaths.map((path): RegExp => new RegExp(path, 'u'));
  }

  public async handle(input: PermissionReaderInput): Promise<AllowedModesMap> {
    if (!input.credentials.agent?.webId) {
      this.logger.debug(`No WebID found, ABAC has no opinion on this request.`);
      return new IdentifierSetMultiMap();
    }
    return (await this.prepare(input)).allowedModes;
  }

  /** Shares the request's resolved attributes with the owner channel, without exposing the assignments over HTTP. */
  public async prepare({ credentials, requestedModes }: PermissionReaderInput):
  Promise<{ context: AbacRequestContext; allowedModes: AllowedModesMap }> {
    const context = await this.contextBuilder.build(credentials, requestedModes.distinctKeys());
    const allowedModes: AllowedModesMap = new IdentifierSetMultiMap();
    const webId = credentials.agent?.webId;
    if (!webId) {
      return { context, allowedModes };
    }
    let rules: Rule[];
    try {
      rules = this.getValidRules(getRules(await this.loader.readRules()), [ ...context.definitions.values() ]);
    } catch (error: unknown) {
      this.logger.warn(`Ignoring allowed modes from unreadable catalogue rules: ${createErrorMessage(error)}`);
      return { context, allowedModes };
    }

    for (const target of requestedModes.distinctKeys()) {
      if (this.isExcluded(target)) {
        this.logger.debug(`ABAC will not allow anything on the excluded resource ${target.path}`);
        continue;
      }
      const vector = context.vectors.get(target)!;
      const modes = evaluateRules(rules, vector);
      this.logger.debug(
        `ABAC allows ${webId} [${[ ...modes ].join(', ')}] on ${target.path}: ${JSON.stringify(vector)}`,
      );
      allowedModes.set(target, modes);
    }
    return { context, allowedModes };
  }

  /**
   * The rules that can match, given the attribute definitions. Warns about each of the others.
   */
  private getValidRules(rules: Iterable<Rule>, definitions: AttributeDefinition[]): Rule[] {
    const defined = new Map(definitions.map((definition): [string, AttributeDefinition] =>
      [ definition.iri, definition ]));
    return [ ...rules ].filter((rule): boolean => {
      const problem = this.findProblem(rule, defined);
      if (problem) {
        this.logger.warn(`Rule ${rule.iri} never matches, as it ${problem}`);
      }
      return !problem;
    });
  }

  /**
   * Why the given rule can never match, if it cannot: it names an attribute without a valid definition,
   * or a value outside its attribute's value space, or it does not condition on the resource.
   * A rule conditions on the resource through an `allOf` condition on a resource attribute,
   * or an `anyOf` whose conditions all are, so it only reaches what has been labelled.
   * A `noneOf` condition narrows a rule, but would still let it reach every resource nobody labelled.
   */
  private findProblem(rule: Rule, defined: Map<string, AttributeDefinition>): string | undefined {
    const conditions = [ ...rule.allOf, ...rule.anyOf, ...rule.noneOf ];
    const undefinedAttributes = new Set(conditions.map(({ attribute }): string => attribute)
      .filter((attribute): boolean => !defined.has(attribute)));
    if (undefinedAttributes.size > 0) {
      return `names undefined attributes: ${[ ...undefinedAttributes ].join(', ')}`;
    }
    const foreignValues = new Set(conditions.flatMap(({ attribute, values }): string[] =>
      values.filter((value): boolean => !defined.get(attribute)!.values.has(value))));
    if (foreignValues.size > 0) {
      return `names values outside their attributes' value spaces: ${[ ...foreignValues ].join(', ')}`;
    }
    const isScoped = rule.allOf.some((condition): boolean => isOnResource(condition, defined)) ||
      (rule.anyOf.length > 0 && rule.anyOf.every((condition): boolean => isOnResource(condition, defined)));
    if (!isScoped) {
      return 'does not condition on the resource, through allOf or an anyOf naming only resource attributes';
    }
  }

  /**
   * Whether the given identifier is outside the server's identifier space or matches one of the excluded paths.
   * The `PathBasedReader` veto does not cover `/.internal/` here: `AuxiliaryReader` has already rewritten it
   * to its subject resource, the root without a trailing slash, which is outside that space.
   * The excluded paths apply only below the base URL, where the server keeps its own namespaces;
   * a pod on a subdomain holds nothing but its owner's data.
   */
  private isExcluded(identifier: ResourceIdentifier): boolean {
    if (!this.identifierStrategy.supportsIdentifier(identifier)) {
      return true;
    }
    if (!identifier.path.startsWith(this.baseUrl)) {
      return false;
    }
    const relative = identifier.path.slice(trimTrailingSlashes(this.baseUrl).length);
    return this.excludePaths.some((regex): boolean => regex.test(relative));
  }
}

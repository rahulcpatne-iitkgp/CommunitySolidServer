import { DataFactory } from 'n3';
import type { NamedNode } from '@rdfjs/types';
import type { Credentials } from '../../authentication/Credentials';
import { isRequestEnvironment } from '../../authentication/EnvironmentCredentialsExtractor';
import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../../logging/LogUtil';
import type { IdentifierStrategy } from '../../util/identifiers/IdentifierStrategy';
import { IdentifierMap } from '../../util/map/IdentifierMap';
import { ABAC } from '../../util/Vocabularies';
import type { AttributeDefinition, AttributeVector } from './AbacTypes';
import type { AbacDataLoader } from './AbacDataLoader';
import { buildAttributeVector, buildEnvironmentVector, getAttributeDefinitions } from './AbacUtil';
import type { EnvironmentAttributeResolver } from './EnvironmentAttributeResolver';

export interface AbacRequestContext {
  definitions: ReadonlyMap<string, AttributeDefinition>;
  vectors: IdentifierMap<AttributeVector>;
}

/** Builds one authoritative attribute context for all targets in a permission-reader request. */
export class AbacContextBuilder {
  protected readonly logger = getLoggerFor(this);

  public constructor(
    private readonly loader: AbacDataLoader,
    private readonly identifierStrategy: IdentifierStrategy,
    private readonly environmentResolver: EnvironmentAttributeResolver,
  ) {}

  public async build(credentials: Credentials, targets: Iterable<ResourceIdentifier>): Promise<AbacRequestContext> {
    const [ definitionData, subjectData, resourceData ] = await Promise.all([
      this.loader.readDefinitions(),
      this.loader.readSubjectAttributes(),
      this.loader.readResourceAttributes(),
    ]);
    const definitions = [ ...getAttributeDefinitions(definitionData) ];
    const webId = credentials.agent?.webId;
    const subject = webId ?
        buildAttributeVector(
          definitions.filter(({ appliesTo }): boolean => appliesTo === ABAC.Subject),
          subjectData,
          [ DataFactory.namedNode(webId) ],
        ) :
        {};
    const environmentDefinitions = definitions.filter(({ appliesTo }): boolean => appliesTo === ABAC.Environment);
    let environment: AttributeVector = {};
    if (environmentDefinitions.length > 0) {
      if (!isRequestEnvironment(credentials.environment)) {
        this.logger.warn(`No request context was recorded, so environment attributes fall back to their defaults.`);
      }
      const resolved = isRequestEnvironment(credentials.environment) ?
          this.environmentResolver.resolve(credentials.environment) :
          {};
      environment = buildEnvironmentVector(environmentDefinitions, resolved);
    }
    const resourceDefinitions = definitions.filter(({ appliesTo }): boolean => appliesTo === ABAC.Resource);
    const vectors = new IdentifierMap<AttributeVector>();
    for (const target of targets) {
      vectors.set(target, {
        ...subject,
        ...environment,
        ...this.identifierStrategy.supportsIdentifier(target) ?
            buildAttributeVector(resourceDefinitions, resourceData, this.getAncestors(target)) :
            {},
      });
    }
    return { definitions: new Map(definitions.map((definition): [string, AttributeDefinition] =>
      [ definition.iri, definition ])), vectors };
  }

  /** The resource followed by its ancestors, most specific first. */
  private getAncestors(identifier: ResourceIdentifier): NamedNode[] {
    const ancestors = [ DataFactory.namedNode(identifier.path) ];
    while (!this.identifierStrategy.isRootContainer(identifier)) {
      identifier = this.identifierStrategy.getParentContainer(identifier);
      ancestors.push(DataFactory.namedNode(identifier.path));
    }
    return ancestors;
  }
}

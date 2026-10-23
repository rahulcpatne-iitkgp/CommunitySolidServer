import type { Quad } from '@rdfjs/types';
import { Store } from 'n3';
import type { Representation } from '../../http/representation/Representation';
import type { RepresentationPreferences } from '../../http/representation/RepresentationPreferences';
import type { ResourceIdentifier } from '../../http/representation/ResourceIdentifier';
import { getLoggerFor } from '../../logging/LogUtil';
import type { ResourceStore } from '../../storage/ResourceStore';
import { INTERNAL_QUADS } from '../../util/ContentTypes';
import { createErrorMessage } from '../../util/errors/ErrorUtil';
import { InternalServerError } from '../../util/errors/InternalServerError';
import { NotFoundHttpError } from '../../util/errors/NotFoundHttpError';
import { isContainerIdentifier, joinUrl } from '../../util/PathUtil';
import { readableToQuads } from '../../util/StreamUtil';
import { LDP } from '../../util/Vocabularies';
import { getMirroredResource, isWithin } from './AbacUtil';

/**
 * Reads the ABAC store through the {@link ResourceStore} directly, bypassing authorization,
 * as `AcpReader` does for ACR documents. A missing store reads as empty.
 *
 * A document in the `resources/` subtree only assigns attributes to the resource it mirrors
 * and to what lies beneath it, so its location alone decides what it can label.
 * That is what lets a pod owner read the part mirroring their pod without seeing labels on another.
 */
export class AbacDataLoader {
  protected readonly logger = getLoggerFor(this);

  private readonly store: ResourceStore;
  private readonly definitionsContainer: string;
  private readonly subjectsContainer: string;
  private readonly resourcesContainer: string;
  private readonly rulesContainer: string;

  /**
   * @param store - Used to read the ABAC store's documents.
   * @param baseUrl - Base URL of the server.
   * @param container - Path of the ABAC store relative to the base URL.
   */
  public constructor(store: ResourceStore, baseUrl: string, container = '.abac/') {
    this.store = store;
    const root = joinUrl(baseUrl, container);
    this.definitionsContainer = joinUrl(root, 'definitions/');
    this.subjectsContainer = joinUrl(root, 'subjects/');
    this.resourcesContainer = joinUrl(root, 'resources/');
    this.rulesContainer = joinUrl(root, 'rules/');
  }

  /** All attribute definitions found in the store. */
  public async readDefinitions(): Promise<Store> {
    return this.readContainer({ path: this.definitionsContainer });
  }

  /** All subject attribute assignments found in the store. */
  public async readSubjectAttributes(): Promise<Store> {
    return this.readContainer({ path: this.subjectsContainer });
  }

  /** All resource attribute assignments found in the store, each about what its document mirrors. */
  public async readResourceAttributes(): Promise<Store> {
    return this.readContainer({ path: this.resourcesContainer }, (document, quads): Quad[] =>
      this.selectMirrored(document, quads));
  }

  /** All rules of the global catalogue. */
  public async readRules(): Promise<Store> {
    return this.readContainer({ path: this.rulesContainer });
  }

  /**
   * Merges the quads of every document in the given container and its nested containers,
   * keeping those of each document that the given function selects.
   */
  private async readContainer(
    identifier: ResourceIdentifier,
    select = (document: string, quads: Quad[]): Quad[] => quads,
  ): Promise<Store> {
    const result = new Store();
    const container = await this.safelyGetResource(identifier, {});
    if (!container) {
      this.logger.debug(`No ABAC container found at ${identifier.path}`);
      return result;
    }
    // Only the metadata is needed, but the data stream still has to be released or its lock leaks.
    container.data.destroy();

    for (const term of container.metadata.getAll(LDP.terms.contains)) {
      const child = { path: term.value };
      if (isContainerIdentifier(child)) {
        result.addQuads((await this.readContainer(child, select)).getQuads(null, null, null, null));
        continue;
      }
      const document = await this.safelyGetResource(child, { type: { [INTERNAL_QUADS]: 1 }});
      if (!document) {
        continue;
      }
      result.addQuads(select(child.path, (await readableToQuads(document.data)).getQuads(null, null, null, null)));
    }
    return result;
  }

  /**
   * The quads of the given `resources/` document about the resource it mirrors or what lies beneath it.
   * Warns about the others, as the document cannot assign them.
   */
  private selectMirrored(document: string, quads: Quad[]): Quad[] {
    const scope = getMirroredResource(document, this.resourcesContainer)!;
    const strays = new Set(quads.map((quad): string => quad.subject.value)
      .filter((subject): boolean => !isWithin(subject, scope)));
    if (strays.size > 0) {
      this.logger.warn(`Ignoring the assignments in ${document} about ${[ ...strays ].join(', ')}, ` +
        `as it only labels ${scope} and what lies beneath it`);
    }
    return quads.filter((quad): boolean => !strays.has(quad.subject.value));
  }

  /**
   * Returns the representation for the given identifier, or `undefined` if it does not exist.
   */
  private async safelyGetResource(identifier: ResourceIdentifier, preferences: RepresentationPreferences):
  Promise<Representation | undefined> {
    try {
      return await this.store.getRepresentation(identifier, preferences);
    } catch (error: unknown) {
      if (!NotFoundHttpError.isInstance(error)) {
        const message = `Error reading ABAC resource ${identifier.path}: ${createErrorMessage(error)}`;
        this.logger.error(message);
        throw new InternalServerError(message, { cause: error });
      }
    }
  }
}

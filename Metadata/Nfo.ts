#!/usr/bin/env deno run --allow-read

import { BasePlugin, PluginInfo, PluginInput } from "../base_plugin.ts";

type AdjacentFilesResponse = {
  archiveId: string;
  baseDir: string;
  count: number;
  files: string[];
};

type ExtractAdjacentResponse = {
  archiveId: string;
  fileName: string;
  outputPath: string;
  relativePath: string;
  size: number;
};

type TankoubonArchivesResponse = {
  tankoubonId: string;
  archiveIds: string[];
};

type EpisodeMeta = {
  title: string;
  summary: string;
  season: number;
  episode: number;
};

type SourceTagCandidate = {
  tag: string;
  score: number;
};

type SeasonMeta = {
  title: string;
  summary: string;
  sourceTag: string;
  genreTags: string[];
  seasonNumber: number;
  cover: string;
};

class NfoMetadataPlugin extends BasePlugin {
  getPluginInfo(): PluginInfo {
    return {
      name: "NFO Sidecar",
      type: "metadata",
      namespace: "nfo",
      author: "codex",
      version: "1.2.1",
      description:
        "Parses season/tvshow/episode NFO files, applies per-file page metadata by path, episode sorting, and cover hiding.",
      parameters: [
        {
          name: "hide_thumb_images",
          type: "bool",
          desc: "Hide sidecar thumb/cover images from files list when episode NFO exists",
          default_value: "1",
        },
        {
          name: "apply_episode_sort",
          type: "bool",
          desc: "Apply season/episode based sort index to media entries",
          default_value: "1",
        },
        {
          name: "include_episode_plot",
          type: "bool",
          desc: "Write episode plot (fallback outline) into page description",
          default_value: "1",
        },
        {
          name: "tag_with_source",
          type: "bool",
          desc: "Add source id tag from NFO uniqueid, e.g. tmdb:4196410",
          default_value: "1",
        },
      ],
      cooldown: 0,
    };
  }

  protected async runPlugin(input: PluginInput): Promise<void> {
    try {
      const params = this.getParams();
      const targetId = String(input.archiveId || "").trim();
      if (!targetId) {
        this.outputResult({ success: false, error: "Missing archiveId/targetId" });
        return;
      }

      const targetType = String((params.__target_type as string) || "archive").trim().toLowerCase();
      const tagWithSource = this.readBoolParam(params, "tag_with_source", true);
      if (targetType === "tankoubon" || targetType === "tank") {
        await this.runTankoubonMode(targetId, tagWithSource);
        return;
      }

      await this.runArchiveMode(targetId, {
        hideThumbImages: this.readBoolParam(params, "hide_thumb_images", true),
        applyEpisodeSort: this.readBoolParam(params, "apply_episode_sort", true),
        includeEpisodePlot: this.readBoolParam(params, "include_episode_plot", true),
        tagWithSource,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.outputResult({ success: false, error: `NFO plugin execution failed: ${message}` });
    }
  }

  private async runArchiveMode(
    archiveId: string,
    options: {
      hideThumbImages: boolean;
      applyEpisodeSort: boolean;
      includeEpisodePlot: boolean;
      tagWithSource: boolean;
    },
  ): Promise<void> {
    this.reportProgress(10, "Listing adjacent files...");
    const listing = await this.callHost<AdjacentFilesResponse>("archive.listAdjacentFiles", { archiveId });
    const files = Array.isArray(listing?.files) ? listing.files.slice() : [];

    const lowerFiles = files.map((f) => ({ raw: f, lower: f.toLowerCase() }));
    const nfoFiles = lowerFiles
      .map((f) => f.raw)
      .filter((file) => file.toLowerCase().endsWith(".nfo"));

    let archiveTitle = "";
    let archiveSummary = "";
    let seasonNumberHint = 0;
    let selectedSource: SourceTagCandidate | null = null;
    const discoveredTags = new Set<string>();
    const pagePatches = new Map<string, Record<string, unknown>>();
    let archiveCover = "";
    let episodeCoverFallback = "";
    let episodeCoverFallbackSort = 0;

    for (const nfoFile of nfoFiles) {
      const lower = nfoFile.toLowerCase();
      const xml = await this.readAdjacentFile(archiveId, nfoFile);
      if (!xml) continue;

      const sourceCandidate = this.parseSourceTagCandidate(xml);
      selectedSource = this.pickBetterSource(selectedSource, sourceCandidate);
      this.addTags(discoveredTags, this.parseGenreTags(xml));

      if (lower === "season.nfo") {
        const seasonTitle = this.readXmlTag(xml, ["title"]).trim();
        const seasonSummary = this.readXmlTag(xml, ["plot"]).trim() || this.readXmlTag(xml, ["outline"]).trim();
        const seasonNumber = this.readXmlInt(xml, ["seasonnumber", "season"]);
        if (seasonNumber > 0) {
          seasonNumberHint = seasonNumber;
        }
        if (seasonTitle) archiveTitle = seasonTitle;
        if (seasonSummary) archiveSummary = seasonSummary;
        continue;
      }
      if (lower === "tvshow.nfo") {
        // tvshow.nfo is useful for collection-level scraping, not archive pages.
        continue;
      }

      const baseName = this.stripExtension(nfoFile);
      const episodeMeta = this.parseEpisodeNfo(xml, nfoFile);
      if (seasonNumberHint <= 0 && episodeMeta.season > 0) {
        seasonNumberHint = episodeMeta.season;
      }
      const mediaPath = this.findBestMediaFile(files, baseName);
      if (!mediaPath) {
        continue;
      }

      const patch: Record<string, unknown> = {
        path: mediaPath,
        title: episodeMeta.title,
      };

      if (options.includeEpisodePlot && episodeMeta.summary) {
        patch.description = episodeMeta.summary;
      }

      if (options.applyEpisodeSort) {
        const sort = this.buildSortIndex(baseName, episodeMeta);
        if (sort > 0) {
          patch.sort = sort;
        }
      }

      pagePatches.set(mediaPath, patch);

      const coverCandidates = this.findCoverCandidates(files, baseName, mediaPath);
      const thumbRelPath = await this.extractBestThumbFromCandidates(archiveId, coverCandidates);
      if (thumbRelPath) {
        patch.thumb = thumbRelPath;
        const sortValue = this.buildSortIndex(baseName, episodeMeta);
        if (
          !episodeCoverFallback ||
          (sortValue > 0 && (episodeCoverFallbackSort <= 0 || sortValue < episodeCoverFallbackSort))
        ) {
          episodeCoverFallback = thumbRelPath;
          episodeCoverFallbackSort = sortValue;
        }
      }

      if (options.hideThumbImages) {
        for (const coverPath of coverCandidates) {
          pagePatches.set(coverPath, {
            path: coverPath,
            hidden_in_files: true,
          });
        }
      }
    }

    archiveCover = await this.findArchiveCoverForArchive(
      archiveId,
      files,
      seasonNumberHint,
      episodeCoverFallback,
    );

    const pages = [...pagePatches.values()];

    let tags = String(this.input?.existingTags || "").trim();
    tags = this.mergeTagList(tags, [...discoveredTags]);
    const parentTvshow = await this.readTvshowInfoForArchive(archiveId);
    tags = this.mergeTagList(tags, parentTvshow.genreTags);
    if (options.tagWithSource && selectedSource?.tag) {
      tags = this.stripGenericNfoSourceTag(tags);
      tags = this.mergeTags(tags, selectedSource.tag);
    } else if (options.tagWithSource) {
      if (parentTvshow.sourceTag) {
        tags = this.stripGenericNfoSourceTag(tags);
        tags = this.mergeTags(tags, parentTvshow.sourceTag);
      }
    }

    this.reportProgress(100, "NFO metadata done");
    this.outputResult({
      success: true,
      data: {
        title: archiveTitle,
        summary: archiveSummary,
        tags,
        cover: archiveCover,
        pages,
      },
    });
  }

  private async runTankoubonMode(tankoubonId: string, tagWithSource: boolean): Promise<void> {
    this.reportProgress(10, "Listing collection archives...");
    const listing = await this.callHost<TankoubonArchivesResponse>("tankoubon.listArchives", {
      tankoubonId,
    });
    const archiveIds = Array.isArray(listing?.archiveIds) ? listing.archiveIds : [];
    const collectionMeta = await this.readTvshowMetadataForTankoubon(archiveIds);

    const patches: Array<Record<string, unknown>> = [];
    for (const archiveId of archiveIds) {
      const seasonMeta = await this.readSeasonMetadata(archiveId);
      if (!seasonMeta) continue;

      let patchTags = "";
      patchTags = this.mergeTagList(patchTags, seasonMeta.genreTags);
      if (tagWithSource) {
        if (seasonMeta.sourceTag) {
          patchTags = this.mergeTags(patchTags, seasonMeta.sourceTag);
        } else if (collectionMeta?.sourceTag) {
          patchTags = this.mergeTags(patchTags, collectionMeta.sourceTag);
        }
      }

      patches.push({
        archive_id: archiveId,
        title: seasonMeta.title,
        summary: seasonMeta.summary,
        tags: patchTags,
        cover: seasonMeta.cover,
      });
    }

    const collectionTags = this.mergeTagList("", collectionMeta?.genreTags || []);
    const outputTags = tagWithSource
      ? this.mergeTags(collectionTags, collectionMeta?.sourceTag || "")
      : collectionTags;
    let collectionCover = collectionMeta?.cover || "";
    if (!collectionCover) {
      for (const patch of patches) {
        const candidate = String(patch.cover || "").trim();
        if (candidate) {
          collectionCover = candidate;
          break;
        }
      }
    }

    this.reportProgress(100, "Collection NFO metadata done");
    this.outputResult({
      success: true,
      data: {
        title: collectionMeta?.title || "",
        summary: collectionMeta?.summary || "",
        tags: outputTags,
        cover: collectionCover,
        archives: patches,
      },
    });
  }

  private readBoolParam(params: Record<string, unknown>, key: string, defaultValue: boolean): boolean {
    const value = params[key];
    if (value === undefined || value === null) return defaultValue;
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value !== 0;
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (normalized === "") return defaultValue;
      if (["0", "false", "no", "n", "off"].includes(normalized)) return false;
      if (["1", "true", "yes", "y", "on"].includes(normalized)) return true;
    }
    return Boolean(value);
  }

  private addTags(target: Set<string>, tags: string[]): void {
    for (const tag of tags) {
      const normalized = String(tag || "").trim();
      if (!normalized) continue;
      target.add(normalized);
    }
  }

  private async readSeasonMetadata(
    archiveId: string,
  ): Promise<SeasonMeta | null> {
    try {
      const listing = await this.callHost<AdjacentFilesResponse>("archive.listAdjacentFiles", { archiveId });
      const files = Array.isArray(listing?.files) ? listing.files : [];
      const seasonNfo = files.find((f) => f.toLowerCase() === "season.nfo");
      if (!seasonNfo) return null;

      const xml = await this.readAdjacentFile(archiveId, seasonNfo);
      if (!xml) return null;
      const seasonNumber =
        this.readXmlInt(xml, ["seasonnumber", "season"]) ||
        this.extractSeasonNumberFromText(String(listing?.baseDir || ""));
      const cover = await this.findArchiveCoverForArchive(archiveId, files, seasonNumber, "");

      return {
        title: this.readXmlTag(xml, ["title"]).trim(),
        summary: this.readXmlTag(xml, ["plot"]).trim() || this.readXmlTag(xml, ["outline"]).trim(),
        sourceTag: this.parseSourceTag(xml),
        genreTags: this.parseGenreTags(xml),
        seasonNumber,
        cover,
      };
    } catch {
      return null;
    }
  }

  private async readTvshowMetadataForTankoubon(
    archiveIds: string[],
  ): Promise<{ title: string; summary: string; sourceTag: string; genreTags: string[]; cover: string } | null> {
    const visitedBaseDirs = new Set<string>();

    for (const archiveId of archiveIds) {
      try {
        const listing = await this.callHost<AdjacentFilesResponse>("archive.listAdjacentFiles", {
          archiveId,
          levelsUp: 1,
        });
        const files = Array.isArray(listing?.files) ? listing.files : [];
        const baseDir = String(listing?.baseDir || "").trim();
        if (baseDir) {
          if (visitedBaseDirs.has(baseDir)) {
            continue;
          }
          visitedBaseDirs.add(baseDir);
        }

        const tvshowNfo = files.find((f) => f.toLowerCase() === "tvshow.nfo");
        if (!tvshowNfo) continue;

        const xml = await this.readAdjacentFile(archiveId, tvshowNfo, 1);
        if (!xml) continue;

        const title = this.readXmlTag(xml, ["title"]).trim();
        const summary = this.readXmlTag(xml, ["plot"]).trim() || this.readXmlTag(xml, ["outline"]).trim();
        const sourceTag = this.parseSourceTag(xml);
        const genreTags = this.parseGenreTags(xml);
        const cover = await this.extractBestThumbFromCandidates(archiveId, this.findGeneralCoverCandidates(files), 1);
        if (title || summary || sourceTag || genreTags.length > 0 || cover) {
          return { title, summary, sourceTag, genreTags, cover };
        }
      } catch {
        // keep trying other archives in the collection
      }
    }

    return null;
  }

  private async readTvshowInfoForArchive(archiveId: string): Promise<{ sourceTag: string; genreTags: string[] }> {
    try {
      const listing = await this.callHost<AdjacentFilesResponse>("archive.listAdjacentFiles", {
        archiveId,
        levelsUp: 1,
      });
      const files = Array.isArray(listing?.files) ? listing.files : [];
      const tvshowNfo = files.find((f) => f.toLowerCase() === "tvshow.nfo");
      if (!tvshowNfo) return { sourceTag: "", genreTags: [] };
      const xml = await this.readAdjacentFile(archiveId, tvshowNfo, 1);
      if (!xml) return { sourceTag: "", genreTags: [] };
      return {
        sourceTag: this.parseSourceTag(xml),
        genreTags: this.parseGenreTags(xml),
      };
    } catch {
      return { sourceTag: "", genreTags: [] };
    }
  }

  private async readAdjacentFile(archiveId: string, fileName: string, levelsUp = 0): Promise<string> {
    const extracted = await this.extractAdjacentFileToCache(archiveId, fileName, levelsUp);
    return await Deno.readTextFile(String(extracted.outputPath));
  }

  private async extractAdjacentFileToCache(
    archiveId: string,
    fileName: string,
    levelsUp = 0,
  ): Promise<ExtractAdjacentResponse> {
    return await this.callHost<ExtractAdjacentResponse>("archive.extractAdjacentFileToCache", {
      archiveId,
      fileName,
      pluginDir: String(this.input?.pluginDir || ""),
      cacheSubdir: "cache",
      levelsUp,
      overwrite: true,
    });
  }

  private async extractBestThumbFromCandidates(
    archiveId: string,
    coverCandidates: string[],
    levelsUp = 0,
  ): Promise<string> {
    for (const candidate of coverCandidates) {
      try {
        const extracted = await this.extractAdjacentFileToCache(archiveId, candidate, levelsUp);
        const relPath = String(extracted.relativePath || "").trim();
        if (relPath) {
          return relPath;
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        await this.logWarn("Failed to extract thumb candidate", {
          archiveId,
          candidate,
          levelsUp,
          error: message,
        });
      }
    }
    return "";
  }

  private parseEpisodeNfo(xml: string, fileName: string): EpisodeMeta {
    const title = this.readXmlTag(xml, ["title"]).trim() || this.stripExtension(fileName);
    const summary = this.readXmlTag(xml, ["plot"]).trim() || this.readXmlTag(xml, ["outline"]).trim();
    const season = this.readXmlInt(xml, ["season", "seasonnumber"]);
    const episode = this.readXmlInt(xml, ["episode"]);

    return {
      title,
      summary,
      season,
      episode,
    };
  }

  private parseGenreTags(xml: string): string[] {
    const genres = this.readXmlTags(xml, ["genre", "tag"]);
    const out: string[] = [];
    for (const raw of genres) {
      const cleaned = raw.trim();
      if (!cleaned) continue;
      out.push(`genre:${cleaned}`);
    }
    return this.unique(out);
  }

  private readXmlTag(xml: string, tagNames: string[]): string {
    const values = this.readXmlTags(xml, tagNames);
    return values.length > 0 ? values[0] : "";
  }

  private readXmlTags(xml: string, tagNames: string[]): string[] {
    const out: string[] = [];
    for (const tagName of tagNames) {
      const escaped = tagName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(`<${escaped}\\b[^>]*>([\\s\\S]*?)<\\/${escaped}>`, "gi");
      let matched: RegExpExecArray | null;
      while ((matched = regex.exec(xml)) !== null) {
        const rawInner = matched?.[1] || "";
        if (!rawInner) continue;

        // Keep CDATA payload while stripping normal XML tags.
        const withCdata = rawInner.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/gi, "$1");
        const plain = withCdata.replace(/<[^>]+>/g, "").trim();
        const decoded = this.decodeXmlEntities(plain).trim();
        if (decoded) {
          out.push(decoded);
        }
      }
    }
    return this.unique(out);
  }

  private readXmlInt(xml: string, tagNames: string[]): number {
    const raw = this.readXmlTag(xml, tagNames).trim();
    if (!raw) return 0;
    const n = Number.parseInt(raw, 10);
    return Number.isFinite(n) ? n : 0;
  }

  private parseSourceTag(xml: string): string {
    return this.parseSourceTagCandidate(xml)?.tag || "";
  }

  private parseSourceTagCandidate(xml: string): SourceTagCandidate | null {
    const preferred = this.extractBestUniqueId(xml);
    if (preferred) return preferred;

    const directTags: Array<{ keys: string[]; tagType: string; score: number }> = [
      { keys: ["tmdbid", "tmdb"], tagType: "tmdb", score: 450 },
      { keys: ["tvdbid", "tvdb"], tagType: "tvdb", score: 430 },
      { keys: ["imdbid", "imdb"], tagType: "imdb", score: 420 },
      { keys: ["traktid", "trakt"], tagType: "trakt", score: 410 },
    ];

    for (const item of directTags) {
      const value = this.readXmlTag(xml, item.keys).trim();
      if (!value) continue;
      const normalized = this.normalizeSourceValue(item.tagType, value);
      if (!normalized) continue;
      return { tag: `${item.tagType}:${normalized}`, score: item.score };
    }

    return null;
  }

  private extractBestUniqueId(xml: string): SourceTagCandidate | null {
    const regex = /<uniqueid\b([^>]*)>([\s\S]*?)<\/uniqueid>/gi;
    let match: RegExpExecArray | null;
    let best: SourceTagCandidate | null = null;

    while ((match = regex.exec(xml)) !== null) {
      const attrsRaw = match[1] || "";
      const rawValue = this.decodeXmlEntities(String(match[2] || "").replace(/<[^>]+>/g, "").trim());
      if (!rawValue) continue;

      const type = this.readAttrValue(attrsRaw, "type").toLowerCase();
      if (!type) continue;

      const normalizedType = this.normalizeSourceType(type);
      if (!normalizedType) continue;

      const normalizedValue = this.normalizeSourceValue(normalizedType, rawValue);
      if (!normalizedValue) continue;

      const defaultAttr = this.readAttrValue(attrsRaw, "default").toLowerCase();
      const isDefault = defaultAttr === "true" || defaultAttr === "1" || defaultAttr === "yes";
      const score = this.sourceTypePriority(normalizedType) + (isDefault ? 100 : 0);
      const candidate: SourceTagCandidate = {
        tag: `${normalizedType}:${normalizedValue}`,
        score,
      };
      best = this.pickBetterSource(best, candidate);
    }

    return best;
  }

  private readAttrValue(attrsRaw: string, attrName: string): string {
    const escaped = attrName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`${escaped}\\s*=\\s*["']([^"']+)["']`, "i");
    const matched = attrsRaw.match(regex);
    return matched?.[1]?.trim() || "";
  }

  private sourceTypePriority(type: string): number {
    const order: Record<string, number> = {
      tmdb: 900,
      tvdb: 800,
      imdb: 700,
      trakt: 600,
    };
    return order[type] || 500;
  }

  private normalizeSourceType(type: string): string {
    const t = type.trim().toLowerCase();
    if (!t) return "";
    const map: Record<string, string> = {
      tmdb: "tmdb",
      themoviedb: "tmdb",
      tvdb: "tvdb",
      thetvdb: "tvdb",
      imdb: "imdb",
      trakt: "trakt",
    };
    return map[t] || t;
  }

  private normalizeSourceValue(type: string, value: string): string {
    const trimmed = value.trim();
    if (!trimmed) return "";
    if (type === "imdb") {
      const pure = trimmed.replace(/^tt/i, "");
      if (!/^\d+$/.test(pure)) return "";
      return `tt${pure}`;
    }
    return trimmed;
  }

  private pickBetterSource(
    current: SourceTagCandidate | null,
    candidate: SourceTagCandidate | null,
  ): SourceTagCandidate | null {
    if (!candidate) return current;
    if (!current) return candidate;
    if (candidate.score > current.score) return candidate;
    return current;
  }

  private findBestMediaFile(files: string[], baseName: string): string {
    const baseLower = baseName.toLowerCase();
    const byStem = files.filter((f) => this.stripExtension(f).toLowerCase() === baseLower);
    if (byStem.length === 0) return "";

    const video = byStem.find((f) => this.isVideoFile(f));
    if (video) return video;

    const image = byStem.find((f) => this.isImageFile(f));
    return image || "";
  }

  private findCoverCandidates(files: string[], baseName: string, selectedMedia: string): string[] {
    const out: Array<{ path: string; score: number }> = [];
    const baseLower = baseName.toLowerCase();
    const selectedLower = selectedMedia.toLowerCase();

    for (const file of files) {
      const lower = file.toLowerCase();
      if (lower === selectedLower) continue;
      if (!this.isImageFile(file)) continue;

      const stem = this.stripExtension(file).toLowerCase();
      const matchesStem = stem === baseLower || stem === `${baseLower}-thumb` || stem === `${baseLower}_thumb`;
      const matchesLoose = stem.startsWith(baseLower) && (stem.includes("thumb") || stem.includes("poster"));
      if (matchesStem || matchesLoose) {
        out.push({ path: file, score: this.scoreCoverCandidate(stem, baseLower) });
      }
    }

    out.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
    return this.unique(out.map((item) => item.path));
  }

  private async findArchiveCoverForArchive(
    archiveId: string,
    sameDirFiles: string[],
    seasonNumber: number,
    fallbackEpisodeCover: string,
  ): Promise<string> {
    const localSeasonSpecificCandidates = this.findSeasonSpecificCoverCandidates(sameDirFiles, seasonNumber);
    const localSeasonSpecificCover = await this.extractBestThumbFromCandidates(archiveId, localSeasonSpecificCandidates);
    if (localSeasonSpecificCover) {
      return localSeasonSpecificCover;
    }

    let parentFiles: string[] = [];
    try {
      const parentListing = await this.callHost<AdjacentFilesResponse>("archive.listAdjacentFiles", {
        archiveId,
        levelsUp: 1,
      });
      parentFiles = Array.isArray(parentListing?.files) ? parentListing.files : [];
      const parentSeasonSpecificCandidates = this.findSeasonSpecificCoverCandidates(parentFiles, seasonNumber);
      const parentSeasonSpecificCover = await this.extractBestThumbFromCandidates(
        archiveId,
        parentSeasonSpecificCandidates,
        1,
      );
      if (parentSeasonSpecificCover) {
        return parentSeasonSpecificCover;
      }
    } catch {
      // ignore parent cover lookup errors and keep fallback behavior
    }

    const localSeasonCandidates = this.findSeasonCoverCandidates(sameDirFiles, seasonNumber);
    const localCover = await this.extractBestThumbFromCandidates(archiveId, localSeasonCandidates);
    if (localCover) {
      return localCover;
    }

    try {
      const parentSeasonCandidates = this.findSeasonCoverCandidates(parentFiles, seasonNumber);
      const parentSeasonCover = await this.extractBestThumbFromCandidates(archiveId, parentSeasonCandidates, 1);
      if (parentSeasonCover) {
        return parentSeasonCover;
      }

      const parentGeneralCover = await this.extractBestThumbFromCandidates(
        archiveId,
        this.findGeneralCoverCandidates(parentFiles),
        1,
      );
      if (parentGeneralCover) {
        return parentGeneralCover;
      }
    } catch {
      // ignore parent cover lookup errors and keep fallback behavior
    }

    return fallbackEpisodeCover || "";
  }

  private findSeasonSpecificCoverCandidates(files: string[], seasonNumber: number): string[] {
    const seasonTokens = this.buildSeasonTokens(seasonNumber);
    if (seasonTokens.length === 0) {
      return [];
    }

    const out: Array<{ path: string; score: number }> = [];
    for (const file of files) {
      if (!this.isImageFile(file)) continue;
      const stem = this.stripExtension(file).toLowerCase();
      if (this.looksLikeEpisodeStem(stem)) continue;

      let score = 0;
      for (const token of seasonTokens) {
        if (!token) continue;
        if (stem === `${token}-poster` || stem === `${token}_poster`) {
          score = Math.max(score, 1600);
        } else if (stem === token) {
          score = Math.max(score, 1500);
        } else if (stem.includes(token) && stem.includes("poster")) {
          score = Math.max(score, 1450);
        } else if (stem.includes(token) && stem.includes("cover")) {
          score = Math.max(score, 1350);
        } else if (stem.includes(token) && stem.includes("thumb")) {
          score = Math.max(score, 1250);
        } else if (stem.includes(token)) {
          score = Math.max(score, 1150);
        }
      }

      if (score > 0) {
        out.push({ path: file, score });
      }
    }

    out.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
    return this.unique(out.map((item) => item.path));
  }

  private findSeasonCoverCandidates(files: string[], seasonNumber: number): string[] {
    const seasonTokens = this.buildSeasonTokens(seasonNumber);
    const out: Array<{ path: string; score: number }> = [];
    for (const file of files) {
      if (!this.isImageFile(file)) continue;
      const stem = this.stripExtension(file).toLowerCase();
      if (this.looksLikeEpisodeStem(stem)) continue;

      let score = this.scoreGeneralCoverCandidate(stem);
      for (const token of seasonTokens) {
        if (!token) continue;
        if (stem === token || stem === `${token}-poster` || stem === `${token}_poster`) {
          score = Math.max(score, 1300);
        } else if (stem.includes(token) && stem.includes("poster")) {
          score = Math.max(score, 1200);
        } else if (stem.includes(token) && stem.includes("cover")) {
          score = Math.max(score, 1100);
        } else if (stem.includes(token) && stem.includes("thumb")) {
          score = Math.max(score, 1000);
        }
      }

      if (score > 0) {
        out.push({ path: file, score });
      }
    }
    out.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
    return this.unique(out.map((item) => item.path));
  }

  private findGeneralCoverCandidates(files: string[]): string[] {
    const out: Array<{ path: string; score: number }> = [];
    for (const file of files) {
      if (!this.isImageFile(file)) continue;
      const stem = this.stripExtension(file).toLowerCase();
      if (this.looksLikeEpisodeStem(stem)) continue;
      const score = this.scoreGeneralCoverCandidate(stem);
      if (score > 0) {
        out.push({ path: file, score });
      }
    }
    out.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
    return this.unique(out.map((item) => item.path));
  }

  private scoreGeneralCoverCandidate(stemLower: string): number {
    if (stemLower === "poster") return 1000;
    if (stemLower === "folder") return 980;
    if (stemLower === "cover") return 960;
    if (stemLower === "thumb") return 940;
    if (stemLower === "landscape") return 900;
    if (stemLower === "backdrop") return 850;
    if (stemLower === "fanart") return 800;
    if (stemLower.includes("poster")) return 700;
    if (stemLower.includes("cover")) return 650;
    if (stemLower.includes("thumb")) return 620;
    if (stemLower.includes("backdrop") || stemLower.includes("fanart")) return 600;
    return 0;
  }

  private buildSeasonTokens(seasonNumber: number): string[] {
    if (!Number.isFinite(seasonNumber) || seasonNumber <= 0) return [];
    const n = Math.trunc(seasonNumber);
    const nn = String(n).padStart(2, "0");
    return this.unique([
      `season${n}`,
      `season${nn}`,
      `season_${n}`,
      `season_${nn}`,
      `season-${n}`,
      `season-${nn}`,
      `season ${n}`,
      `season ${nn}`,
      `s${n}`,
      `s${nn}`,
    ]);
  }

  private looksLikeEpisodeStem(stemLower: string): boolean {
    return /s\d{1,3}e\d{1,4}/i.test(stemLower);
  }

  private extractSeasonNumberFromText(text: string): number {
    const source = String(text || "");
    if (!source) return 0;
    const matched = source.match(/season[\s_\-]?(\d{1,3})/i) || source.match(/\bs(\d{1,3})\b/i);
    if (!matched?.[1]) return 0;
    const value = Number.parseInt(matched[1], 10);
    return Number.isFinite(value) ? value : 0;
  }

  private scoreCoverCandidate(stemLower: string, baseLower: string): number {
    if (stemLower === `${baseLower}-thumb` || stemLower === `${baseLower}_thumb`) return 100;
    if (stemLower === `${baseLower}.thumb`) return 95;
    if (stemLower === `${baseLower}-poster` || stemLower === `${baseLower}_poster`) return 90;
    if (stemLower === `${baseLower}-cover` || stemLower === `${baseLower}_cover`) return 80;
    if (stemLower.includes("thumb")) return 70;
    if (stemLower.includes("poster")) return 60;
    if (stemLower.includes("cover")) return 50;
    if (stemLower === baseLower) return 10;
    return 1;
  }

  private buildSortIndex(baseName: string, meta: EpisodeMeta): number {
    if (meta.season > 0 && meta.episode > 0) {
      return meta.season * 10000 + meta.episode;
    }

    const m = baseName.match(/S(\d{1,3})E(\d{1,4})/i);
    if (!m) return 0;
    const season = Number.parseInt(m[1], 10);
    const episode = Number.parseInt(m[2], 10);
    if (!Number.isFinite(season) || !Number.isFinite(episode)) return 0;
    return season * 10000 + episode;
  }

  private isVideoFile(name: string): boolean {
    return /\.(mp4|mkv|webm|avi|mov|m4v)$/i.test(name);
  }

  private isImageFile(name: string): boolean {
    return /\.(jpg|jpeg|png|webp|gif|avif)$/i.test(name);
  }

  private stripExtension(name: string): string {
    const idx = name.lastIndexOf(".");
    if (idx <= 0) return name;
    return name.slice(0, idx);
  }

  private unique(items: string[]): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const item of items) {
      const key = String(item || "").trim();
      if (!key || seen.has(key)) continue;
      seen.add(key);
      out.push(key);
    }
    return out;
  }

  private mergeTags(existing: string, additions: string): string {
    const split = (s: string) =>
      s
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);

    const merged = this.unique([...split(existing), ...split(additions)]);
    return merged.join(", ");
  }

  private mergeTagList(existing: string, additions: string[]): string {
    const split = (s: string) =>
      s
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);

    const merged = this.unique([
      ...split(existing),
      ...additions.map((x) => String(x || "").trim()).filter(Boolean),
    ]);
    return merged.join(", ");
  }

  private stripGenericNfoSourceTag(tags: string): string {
    const filtered = tags
      .split(",")
      .map((x) => x.trim())
      .filter((x) => x && x.toLowerCase() !== "source:nfo");
    return this.unique(filtered).join(", ");
  }

  private decodeXmlEntities(input: string): string {
    return input
      .replace(/&quot;/g, "\"")
      .replace(/&apos;/g, "'")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&amp;/g, "&")
      .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
      .replace(/&#([0-9]+);/g, (_, dec) => String.fromCodePoint(Number.parseInt(dec, 10)));
  }
}

if (import.meta.main) {
  const plugin = new NfoMetadataPlugin();
  await plugin.handleCommand();
}

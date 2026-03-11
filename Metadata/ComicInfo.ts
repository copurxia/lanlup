#!/usr/bin/env deno run --allow-read

import { BasePlugin, PluginInfo, PluginInput } from "../base_plugin.ts";

type ArchiveFilesResponse = { archiveId: string; count: number; files: string[] };
type ExtractToCacheResponse = { archiveId: string; entryName: string; outputPath: string; relativePath: string; size: number };

class ComicInfoMetadataPlugin extends BasePlugin {
  getPluginInfo(): PluginInfo {
    return {
      name: "ComicInfo",
      type: "metadata",
      namespace: "comicinfo",
      author: "copur",
      version: "1.0",
      description: "Reads ComicInfo.xml from archive and imports title, tags, artist, source and release date.",
      parameters: [
        { name: "comicinfo_name", type: "string", desc: "Preferred ComicInfo filename inside archive", default_value: "ComicInfo.xml" },
        { name: "merge_existing", type: "bool", desc: "Merge extracted tags with existing archive tags", default_value: "1" },
        { name: "include_writer_artist", type: "bool", desc: "Add artist:<Writer> tag", default_value: "1" },
        { name: "include_web_source", type: "bool", desc: "Map <Web> to metadata.source_url", default_value: "1" },
        { name: "include_release_date", type: "bool", desc: "Map Year/Month/Day to metadata.release_at (unix epoch seconds)", default_value: "1" },
      ],
      oneshot_arg: "Optional ComicInfo filename inside archive (e.g. ComicInfo.xml)",
      cooldown: 0,
    };
  }

  protected async runPlugin(input: PluginInput): Promise<void> {
    try {
      this.reportProgress(5, "扫描归档内 ComicInfo 元数据文件...");
      const params = this.getParams();
      const archiveId = String(input.targetId || "").trim();
      if (!archiveId) {
        this.outputResult({ success: false, error: "Missing targetId" });
        return;
      }

      const metadata = this.readMetadataObject(input);
      const preferredFromParam = String(params.comicinfo_name || "ComicInfo.xml").trim();
      const preferredFromOneshot = String(input.oneshotParam || "").trim();
      const preferred = preferredFromOneshot || preferredFromParam || "ComicInfo.xml";
      const mergeExisting = !!params.merge_existing;
      const includeWriterArtist = !!params.include_writer_artist;
      const includeWebSource = !!params.include_web_source;
      const includeReleaseDate = !!params.include_release_date;

      const listing = await this.callHost<ArchiveFilesResponse>("archive.listFiles", { archiveId });
      const files = Array.isArray(listing?.files) ? listing.files : [];
      if (!files.length) {
        this.outputResult({ success: false, error: "No files found in archive" });
        return;
      }

      const entryName = this.pickComicInfoEntry(files, preferred);
      if (!entryName) {
        this.outputResult({ success: false, error: "No ComicInfo.xml found in archive. Preferred: " + preferred });
        return;
      }

      this.reportProgress(35, "读取 " + entryName + " ...");
      const extracted = await this.callHost<ExtractToCacheResponse>("archive.extractFileToCache", {
        archiveId,
        entryName,
        pluginDir: String(input.pluginDir || ""),
        cacheSubdir: "cache",
        overwrite: true,
      });

      const xml = await Deno.readTextFile(String(extracted.outputPath));
      const title = this.firstTagText(xml, "Title");
      const series = this.firstTagText(xml, "Series");
      const summary = this.firstTagText(xml, "Summary");
      const writer = this.firstTagText(xml, "Writer").trim();
      const web = this.firstTagText(xml, "Web").trim();
      const tags = this.splitCsvTags(this.firstTagText(xml, "Tags"));

      if (includeWriterArtist && writer) {
        tags.push("artist:" + writer);
      }

      const deduped = this.dedupeTags(tags).join(", ");
      const mergedTags = mergeExisting ? this.mergeTags(this.metadataTagsToCsv(metadata.tags), deduped) : deduped;
      const releaseAt = includeReleaseDate ? this.parseReleaseAt(xml) : null;

      const next = this.cloneMetadataObject(metadata);
      const nextTitle = title.trim() || series.trim();
      if (nextTitle) {
        next.title = nextTitle;
      }
      if (summary.trim()) {
        next.description = summary.trim();
      }
      next.tags = this.metadataTagsFromCsv(mergedTags);
      if (includeWebSource && web) {
        next.source_url = web;
      }
      if (releaseAt) {
        next.release_at = releaseAt;
      }
      next.children = [];
      delete (next as Record<string, unknown>).archive;
      delete (next as Record<string, unknown>).archive_id;

      this.reportProgress(100, "ComicInfo 元数据导入完成");
      this.outputResult({ success: true, data: next });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.outputResult({ success: false, error: "Plugin execution failed: " + errorMessage });
    }
  }

  private pickComicInfoEntry(files: string[], preferred: string): string | null {
    const preferredTrimmed = preferred.trim();
    if (preferredTrimmed) {
      const exact = files.find((f) => f === preferredTrimmed);
      if (exact) return exact;

      const lowerWanted = preferredTrimmed.toLowerCase();
      const ci = files.find((f) => String(f).toLowerCase() === lowerWanted);
      if (ci) return ci;
    }

    const fallback = files.find((f) => this.baseName(f).toLowerCase() === "comicinfo.xml");
    return fallback || null;
  }

  private baseName(path: string): string {
    const normalized = String(path || "").replace(/\\/g, "/");
    const idx = normalized.lastIndexOf("/");
    return idx >= 0 ? normalized.slice(idx + 1) : normalized;
  }

  private parseReleaseAt(xml: string): string | null {
    const yearText = this.firstTagText(xml, "Year").trim();
    const monthText = this.firstTagText(xml, "Month").trim();
    const dayText = this.firstTagText(xml, "Day").trim();
    if (!yearText || !monthText) return null;

    const year = Number.parseInt(yearText, 10);
    const month = Number.parseInt(monthText, 10);
    const hasDay = dayText !== "";
    const day = hasDay ? Number.parseInt(dayText, 10) : 1;

    if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) {
      return null;
    }
    if (month < 1 || month > 12 || day < 1) {
      return null;
    }

    const ms = Date.UTC(year, month - 1, day, 0, 0, 0, 0);
    if (!Number.isFinite(ms)) return null;

    const d = new Date(ms);
    if (
      d.getUTCFullYear() !== year ||
      d.getUTCMonth() !== month - 1 ||
      d.getUTCDate() !== day
    ) {
      return null;
    }

    return String(Math.floor(ms / 1000));
  }

  private firstTagText(xml: string, tagName: string): string {
    const escaped = tagName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp("<" + escaped + "\\b[^>]*>([\\s\\S]*?)<\\/" + escaped + ">", "i");
    const m = xml.match(re);
    if (!m?.[1]) return "";
    const plain = String(m[1]).replace(/<[^>]+>/g, "").trim();
    return this.decodeXmlEntities(plain).trim();
  }

  private splitCsvTags(input: string): string[] {
    return String(input || "")
      .split(",")
      .map((x) => this.decodeXmlEntities(String(x || "")).trim())
      .filter(Boolean);
  }

  private decodeXmlEntities(input: string): string {
    return input
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&amp;/g, "&")
      .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
      .replace(/&#([0-9]+);/g, (_, dec) => String.fromCodePoint(Number.parseInt(dec, 10)));
  }

  private dedupeTags(tags: string[]): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const raw of tags) {
      const t = String(raw || "").trim();
      if (!t || seen.has(t)) continue;
      seen.add(t);
      out.push(t);
    }
    return out;
  }

  private mergeTags(existing: string, additions: string): string {
    const split = (s: string) =>
      s
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);

    const all = [...split(existing), ...split(additions)];
    return this.dedupeTags(all).join(", ");
  }
}

if (import.meta.main) {
  const plugin = new ComicInfoMetadataPlugin();
  await plugin.handleCommand();
}

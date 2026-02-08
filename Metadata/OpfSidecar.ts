#!/usr/bin/env deno run --allow-read

import { BasePlugin, PluginInfo, PluginInput } from "../base_plugin.ts";

type AdjacentFilesResponse = { archiveId: string; baseDir: string; count: number; files: string[] };
type ExtractAdjacentResponse = { archiveId: string; fileName: string; outputPath: string; relativePath: string; size: number };

class OpfSidecarMetadataPlugin extends BasePlugin {
  getPluginInfo(): PluginInfo {
    return {
      name: "OPF Sidecar",
      type: "metadata",
      namespace: "opfmeta",
      author: "copur",
      version: "1.0",
      description: "Reads adjacent metadata.opf (or custom OPF) and imports dc:subject tags.",
      parameters: [
        { name: "sidecar_name", type: "string", desc: "Preferred OPF sidecar filename", default_value: "metadata.opf" },
        { name: "merge_existing", type: "bool", desc: "Merge extracted tags with existing archive tags", default_value: "1" },
        { name: "include_artist", type: "bool", desc: "Add artist:<dc:creator> tag", default_value: "1" },
        { name: "include_timestamp", type: "bool", desc: "Map calibre:timestamp to updated_at:<unix>", default_value: "1" },
      ],
      oneshot_arg: "Optional OPF filename in archive directory (e.g. metadata.opf)",
      cooldown: 0,
    };
  }

  protected async runPlugin(input: PluginInput): Promise<void> {
    try {
      this.reportProgress(5, "扫描归档旁路元数据文件...");
      const params = this.getParams();
      const archiveId = String(input.archiveId || "").trim();
      if (!archiveId) {
        this.outputResult({ success: false, error: "Missing archiveId" });
        return;
      }

      const preferredFromParam = String(params.sidecar_name || "metadata.opf").trim();
      const preferredFromOneshot = String(input.oneshotParam || "").trim();
      const preferred = preferredFromOneshot || preferredFromParam || "metadata.opf";
      const mergeExisting = !!params.merge_existing;
      const includeArtist = !!params.include_artist;
      const includeTimestamp = !!params.include_timestamp;

      const listing = await this.callHost<AdjacentFilesResponse>("archive.listAdjacentFiles", { archiveId });
      const files = Array.isArray(listing?.files) ? listing.files : [];
      if (!files.length) {
        this.outputResult({ success: false, error: "No adjacent files found" });
        return;
      }

      const opfFile = this.pickOpf(files, preferred);
      if (!opfFile) {
        this.outputResult({
          success: false,
          error: "No OPF sidecar found. Preferred: " + preferred,
        });
        return;
      }

      this.reportProgress(35, "读取 " + opfFile + " ...");
      const extracted = await this.callHost<ExtractAdjacentResponse>("archive.extractAdjacentFileToCache", {
        archiveId,
        fileName: opfFile,
        pluginDir: String(input.pluginDir || ""),
        cacheSubdir: "cache",
        overwrite: true,
      });

      const xml = await Deno.readTextFile(String(extracted.outputPath));
      const title = this.firstTagText(xml, "dc:title");
      const summary = this.firstTagText(xml, "dc:description");

      const tags: string[] = [];
      for (const raw of this.allTagTexts(xml, "dc:subject")) {
        const t = raw.trim();
        if (t) tags.push(t);
      }

      if (includeArtist) {
        const creator = this.firstTagText(xml, "dc:creator").trim();
        if (creator) tags.push("artist:" + creator);
      }

      if (includeTimestamp) {
        const ts = this.readCalibreTimestamp(xml);
        if (ts) tags.push("updated_at:" + ts);
      }

      const deduped = this.dedupeTags(tags).join(", ");
      const merged = mergeExisting ? this.mergeTags(String(input.existingTags || ""), deduped) : deduped;

      this.reportProgress(100, "OPF 元数据导入完成");
      this.outputResult({
        success: true,
        data: {
          title,
          summary,
          tags: merged,
        },
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.outputResult({ success: false, error: "Plugin execution failed: " + errorMessage });
    }
  }

  private pickOpf(files: string[], preferred: string): string | null {
    const preferredTrimmed = preferred.trim();
    if (preferredTrimmed) {
      const exact = files.find((f) => f === preferredTrimmed);
      if (exact) return exact;

      const lowerWanted = preferredTrimmed.toLowerCase();
      const ci = files.find((f) => String(f).toLowerCase() === lowerWanted);
      if (ci) return ci;
    }

    const fallback = files.find((f) => String(f).toLowerCase().endsWith(".opf"));
    return fallback || null;
  }

  private readCalibreTimestamp(xml: string): string | null {
    const m = xml.match(/<meta\b[^>]*\bname\s*=\s*["']calibre:timestamp["'][^>]*\bcontent\s*=\s*["']([^"']+)["'][^>]*\/?\s*>/i);
    if (!m?.[1]) return null;
    const ms = Date.parse(this.decodeXmlEntities(m[1]));
    if (!Number.isFinite(ms)) return null;
    return String(Math.floor(ms / 1000));
  }

  private firstTagText(xml: string, tagName: string): string {
    const all = this.allTagTexts(xml, tagName);
    return all[0] || "";
  }

  private allTagTexts(xml: string, tagName: string): string[] {
    const escaped = tagName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp("<" + escaped + "\\b[^>]*>([\\s\\S]*?)<\\/" + escaped + ">", "gi");
    const out: string[] = [];

    let m: RegExpExecArray | null;
    while ((m = re.exec(xml)) !== null) {
      const raw = (m[1] || "").trim();
      if (!raw) continue;
      const plain = raw.replace(/<[^>]+>/g, "").trim();
      const decoded = this.decodeXmlEntities(plain).trim();
      if (decoded) out.push(decoded);
    }
    return out;
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
      if (!t) continue;
      if (seen.has(t)) continue;
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
  const plugin = new OpfSidecarMetadataPlugin();
  await plugin.handleCommand();
}

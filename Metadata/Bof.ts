#!/usr/bin/env deno run --allow-net --allow-read

import {
  BasePlugin,
  PluginInfo,
  PluginInput,
  PluginResult,
} from "../base_plugin.ts";

type BofSearchItem = {
  id: string;
  title: string;
  author: string;
  date?: string;
};

type BofSeriesInfo = {
  id: string;
  title: string;
  originalTitle: string;
  englishTitle: string;
  summary: string;
  status: string;
  tags: string[];
  authors: string[];
  coverFrameUrl: string;
};

type BofVolumeInfo = {
  id: string;
  title: string;
  coverUrl: string;
};

type VolumeMeta = {
  volume_no: number;
  title: string;
  summary: string;
  tags: string;
  cover?: string;
  release_date?: string;
  isbn?: string;
  source_url: string;
  cover_urls: string[];
};

class BofMetadataPlugin extends BasePlugin {
  private static readonly WEB_BASE = "https://bookof.moe";
  private static readonly USER_AGENT = "lanlu-bof-metadata/1.0";

  getPluginInfo(): PluginInfo {
    return {
      name: "Bookof",
      type: "metadata",
      namespace: "bofmeta",
      author: "lanlu",
      version: "1.0",
      description:
        "Scrapes bookof.moe for series metadata and volume cover info.",
      parameters: [
        {
          name: "search_limit",
          type: "int",
          desc: "Search candidate limit (1-20).",
          default_value: "8",
        },
      ],
      oneshot_arg: "Bookof series URL or series id",
      cooldown: 1,
      permissions: [
        "net=bookof.moe",
        "net=img.bookof.moe",
        "net=kmimg.moex.ink",
        "net=moex.ink",
        "net=mxomo.com",
        "net=img.mxomo.com",
        "net=i.mxomo.com",
        "net=pic.mxomo.com",
      ],
      update_url:
        "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/Bof.ts",
    };
  }

  protected async runPlugin(input: PluginInput): Promise<void> {
    try {
      this.reportProgress(5, "初始化 Bookof 元数据抓取...");
      const params = this.getParams();

      const searchLimit = this.clampInt(Number(params.search_limit ?? 8), 1, 20);

      const seriesId =
        this.extractSeriesId(String(input.oneshotParam || "")) ||
        this.extractSeriesIdFromTags(String(input.existingTags || "")) ||
        await this.searchSeriesId(String(input.archiveTitle || ""), searchLimit);

      if (!seriesId) {
        this.outputResult({
          success: false,
          error:
            "No Bookof series id found. Provide oneshotParam (series URL/ID), source tag, or searchable title.",
        });
        return;
      }

      this.reportProgress(30, "获取 Bookof 系列详情...");
      const seriesUrl = `${BofMetadataPlugin.WEB_BASE}/b/${seriesId}.htm`;
      const seriesHtml = await this.fetchText(seriesUrl);
      if (!seriesHtml) {
        this.outputResult({
          success: false,
          error: `Failed to fetch series page ${seriesUrl}`,
        });
        return;
      }

      const series = this.parseSeriesHtml(seriesId, seriesHtml);
      if (!series || !series.title) {
        this.outputResult({
          success: false,
          error: `Failed to parse series page ${seriesUrl}`,
        });
        return;
      }

      this.reportProgress(55, "获取单行本封面信息...");
      const volumes = series.coverFrameUrl
        ? await this.fetchVolumes(series.coverFrameUrl)
        : [];

      this.reportProgress(80, "构建元数据输出...");
      const fetchedTags = this.buildSeriesTags(series, seriesUrl);
      const mergedTags = fetchedTags;

      const primaryTitle = series.title || series.originalTitle || seriesId;
      const summary = this.cleanSummary(series.summary || "");
      const seriesCoverUrls = this.pickSeriesCoverUrls(volumes);
      let seriesCover = await this.cacheCoverForResult(
        seriesCoverUrls,
        `series_${seriesId}`,
      );
      if (!seriesCover && seriesCoverUrls.length > 0) {
        seriesCover = seriesCoverUrls[0];
      }

      const volumeMetas = await this.buildVolumeMetas(
        volumes,
        seriesUrl,
      );

      this.reportProgress(100, "元数据获取完成");
      this.outputResult({
        success: true,
        data: {
          title: primaryTitle,
          summary,
          tags: mergedTags,
          cover: seriesCover,
          tankoubon: {
            title: primaryTitle,
            summary,
            tags: mergedTags,
            cover: seriesCover,
            source_url: seriesUrl,
          },
          archives: volumeMetas,
        },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.outputResult({
        success: false,
        error: `Plugin execution failed: ${message}`,
      });
    }
  }

  private async fetchText(url: string): Promise<string> {
    const resp = await fetch(url, {
      headers: {
        "user-agent": BofMetadataPlugin.USER_AGENT,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.6",
      },
    });
    if (!resp.ok) return "";
    return await resp.text();
  }

  private extractSeriesId(value: string): string | null {
    const raw = value.trim();
    if (!raw) return null;

    if (/^[0-9a-zA-Z_-]+$/.test(raw)) {
      return raw;
    }

    const m = raw.match(/bookof\.moe\/b\/([^./]+)\.htm/i);
    if (m?.[1]) return m[1];

    return null;
  }

  private extractSeriesIdFromTags(existingTags: string): string | null {
    if (!existingTags) return null;
    const m = existingTags.match(/source:\s*(?:https?:\/\/)?bookof\.moe\/b\/([^\s,]+)\.htm/i);
    if (m?.[1]) return m[1];
    return null;
  }

  private normalizeTitleForSearch(raw: string): string {
    return String(raw || "")
      .replace(/\[[^\]]*\]/g, " ")
      .replace(/\([^)]*\)/g, " ")
      .replace(/（[^）]*）/g, " ")
      .replace(/[._\-:/\\|]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  private async searchSeriesId(title: string, limit: number): Promise<string | null> {
    const normalized = this.normalizeTitleForSearch(title);
    if (!normalized) return null;

    const url = `${BofMetadataPlugin.WEB_BASE}/data_list.php?s=${encodeURIComponent(normalized)}&p=1`;
    const html = await this.fetchText(url);
    if (!html) return null;

    const results = this.parseSearchResults(html);
    if (results.length === 0) return null;

    const scored = results.map((it) => {
      const candidate = this.normalizeTitleForSearch(it.title);
      const score = this.titleSimilarity(normalized, candidate);
      return { id: it.id, score };
    });

    scored.sort((a, b) => b.score - a.score);
    const best = scored[0];
    if (best && best.score > 0) return best.id;

    return results[0]?.id || null;
  }

  private parseSearchResults(html: string): BofSearchItem[] {
    const results: BofSearchItem[] = [];
    const re = /datainfo-B=[^,]*,([^,]+),([^,]*),([^,]*),([0-9-]*)/g;
    let match;
    while ((match = re.exec(html)) !== null) {
      const id = String(match[1] || "").trim();
      const title = this.decodeHtmlEntities(String(match[2] || "").trim());
      const author = this.decodeHtmlEntities(String(match[3] || "").trim());
      const date = String(match[4] || "").trim();
      if (!id || !title) continue;
      results.push({ id, title, author, date });
    }
    return results;
  }

  private parseSeriesHtml(id: string, html: string): BofSeriesInfo | null {
    const titleRaw = this.extractFirst(html, /class="name_main"[^>]*>([\s\S]*?)<\//i);
    const title = this.decodeHtmlEntities(this.stripHtml(titleRaw)).trim();

    const nameSubts = this.extractAll(html, /class="name_subt"[^>]*>([\s\S]*?)<\//gi)
      .map((t) => this.decodeHtmlEntities(this.stripHtml(t)).trim())
      .filter(Boolean);

    let englishTitle = "";
    let infoText = "";
    if (nameSubts.length > 0) {
      const seriesNameStr = nameSubts[0];
      const m = seriesNameStr.match(/\(([^)]+)\)\s*(.*)/);
      if (m?.[1]) englishTitle = m[1].trim();
      infoText = nameSubts.length > 1 ? nameSubts[1] : seriesNameStr;
    }

    const summaryRaw = this.extractFirst(html, /id="div_desctext"[^>]*>([\s\S]*?)<\//i);
    const summary = this.decodeHtmlEntities(this.stripHtml(summaryRaw))
      .replace(/[\r\n]+/g, "\n")
      .replace(/\【.*?\】$/g, "")
      .trim();

    const authors = this.extractAll(
      html,
      /href="https?:\/\/bookof\.moe\/s\/AUT[^"]*"[^>]*>([\s\S]*?)<\//gi,
    )
      .map((t) => this.decodeHtmlEntities(this.stripHtml(t)).trim())
      .filter(Boolean);

    const statusMatch = infoText.match(/[狀状]態[:：]\s*([^\s分類<]+)/);
    const status = statusMatch ? statusMatch[1].trim() : "";

    const tagsMatch = infoText.match(/分[類类][:：]\s*([^\n<]+)/);
    const tags = tagsMatch
      ? tagsMatch[1].trim().split(/\s+/).filter(Boolean)
      : [];

    const coverFrameRaw = this.extractFirst(
      html,
      /window\.iframe_action\.location\.href\s*=\s*['"]([^'"]+)['"]/i,
    );
    let coverFrameUrl = "";
    if (coverFrameRaw) {
      if (/^https?:\/\//i.test(coverFrameRaw)) {
        coverFrameUrl = coverFrameRaw;
      } else {
        coverFrameUrl = `${BofMetadataPlugin.WEB_BASE}${coverFrameRaw.startsWith("/") ? "" : "/"}${coverFrameRaw}`;
      }
    }

    return {
      id,
      title: title || "",
      originalTitle: title || "",
      englishTitle,
      summary,
      status,
      tags,
      authors,
      coverFrameUrl,
    };
  }

  private async fetchVolumes(coverFrameUrl: string): Promise<BofVolumeInfo[]> {
    const html = await this.fetchText(coverFrameUrl);
    if (!html) return [];

    const results: BofVolumeInfo[] = [];
    // Align with KomgaBangumi: datainfo-V=ID,Title,Type,Unknown,CoverURL,Unknown
    const re = /datainfo-V=\d+,[^,]+,[^,]+,[^,]+,([^,]+),[^,]+/g;
    let match;
    while ((match = re.exec(html)) !== null) {
      const coverRaw = String(match[1] || "").trim();
      if (!coverRaw) continue;
      const coverUrl = /^https?:\/\//i.test(coverRaw)
        ? coverRaw
        : `${BofMetadataPlugin.WEB_BASE}${coverRaw.startsWith("/") ? "" : "/"}${coverRaw}`;
      results.push({ id: "", title: "", coverUrl });
    }

    return results;
  }

  private buildSeriesTags(series: BofSeriesInfo, seriesUrl: string): string {
    const tags: string[] = [];
    tags.push(`source:${seriesUrl}`);

    if (series.status) {
      tags.push(series.status);
    }

    if (Array.isArray(series.tags)) {
      tags.push(...series.tags);
    }

    return this.dedupeCsv(tags.join(", "));
  }

  private pickSeriesCoverUrls(volumes: BofVolumeInfo[]): string[] {
    const urls = volumes.map((v) => v.coverUrl).filter(Boolean);
    return Array.from(new Set(urls));
  }

  private async buildVolumeMetas(
    volumes: BofVolumeInfo[],
    seriesUrl: string,
  ): Promise<VolumeMeta[]> {
    const results: VolumeMeta[] = [];
    for (let i = 0; i < volumes.length; i += 1) {
      const vol = volumes[i];
      const bestTitle = vol.title || `Volume ${i + 1}`;
      const volumeNo = this.extractVolumeNo(bestTitle) ?? (i + 1);
      const coverUrls = vol.coverUrl ? [vol.coverUrl] : [];
      let cover = await this.cacheCoverForResult(coverUrls, `vol_${vol.id || i + 1}`);
      if (!cover && coverUrls.length > 0) {
        cover = coverUrls[0];
      }
      const tags = this.mergeCsvTags(
        `source:${seriesUrl}`,
      );

      results.push({
        volume_no: volumeNo,
        title: bestTitle,
        summary: "",
        tags,
        cover,
        source_url: seriesUrl,
        cover_urls: coverUrls,
      });
    }
    return results;
  }

  private extractFirst(input: string, re: RegExp): string {
    const m = input.match(re);
    return m?.[1] ?? "";
  }

  private extractAll(input: string, re: RegExp): string[] {
    const out: string[] = [];
    let match;
    while ((match = re.exec(input)) !== null) {
      if (match[1]) out.push(match[1]);
    }
    return out;
  }

  private stripHtml(input: string): string {
    return String(input || "")
      .replace(/<[^>]*>/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  private decodeHtmlEntities(input: string): string {
    return String(input || "")
      .replace(/&nbsp;/g, " ")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, "\"")
      .replace(/&#39;/g, "'")
      .replace(/&#x27;/g, "'")
      .replace(/&#x2F;/g, "/");
  }

  private cleanSummary(summary: string): string {
    return String(summary || "")
      .replace(/\r\n|\r/g, "\n")
      .split("\n")
      .map((line) => line.trim())
      .join("\n")
      .trim();
  }

  private dedupeCsv(csv: string): string {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const item of String(csv || "").split(",")) {
      const t = item.trim();
      if (!t) continue;
      const key = t.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(t);
    }
    return out.join(", ");
  }

  private mergeCsvTags(...parts: string[]): string {
    return this.dedupeCsv(parts.filter(Boolean).join(","));
  }

  private titleSimilarity(a: string, b: string): number {
    if (!a || !b) return 0;
    if (a === b) return 1;
    const aLower = a.toLowerCase();
    const bLower = b.toLowerCase();
    if (aLower === bLower) return 0.98;
    if (aLower.includes(bLower) || bLower.includes(aLower)) return 0.9;

    const tokensA = new Set(aLower.split(/\s+/).filter(Boolean));
    const tokensB = new Set(bLower.split(/\s+/).filter(Boolean));
    if (tokensA.size === 0 || tokensB.size === 0) return 0;

    let hit = 0;
    for (const t of tokensA) {
      if (tokensB.has(t)) hit += 1;
    }
    return hit / Math.max(tokensA.size, tokensB.size);
  }

  private extractVolumeNo(name: string): number | null {
    if (!name) return null;
    const patterns = [
      /(?:vol(?:ume)?\.?\s*)(\d{1,4})/i,
      /第\s*(\d{1,4})\s*[卷冊册]/i,
      /(\d{1,4})\s*[卷冊册]$/i,
      /\((\d{1,4})\)$/,
      /\b(\d{1,4})\b/,
    ];
    for (const p of patterns) {
      const m = name.match(p);
      if (m?.[1]) {
        const n = Number(m[1]);
        if (Number.isFinite(n) && n > 0) return n;
      }
    }
    return null;
  }

  private clampInt(v: number, min: number, max: number): number {
    if (!Number.isFinite(v)) return min;
    if (v < min) return min;
    if (v > max) return max;
    return Math.trunc(v);
  }

  private async cacheCoverForResult(urls: string[], key: string): Promise<string> {
    if (!Array.isArray(urls) || urls.length === 0) return "";

    const pluginDir = String(this.input?.pluginDir || "").trim();
    const namespace = String(this.getPluginInfo().namespace || "bofmeta").trim();
    if (!pluginDir || !namespace) return "";

    const cacheDir = `${pluginDir}/cache/covers`;
    await Deno.mkdir(cacheDir, { recursive: true });

    const safeKey = String(key || "cover")
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "_")
      .replace(/^_+|_+$/g, "") || "cover";

    for (const rawUrl of urls) {
      const imageUrl = String(rawUrl || "").trim();
      if (!imageUrl) continue;
      try {
        const response = await fetch(imageUrl, {
          headers: {
            "user-agent": BofMetadataPlugin.USER_AGENT,
            "accept": "image/*,*/*;q=0.8",
          },
        });
        if (!response.ok) continue;
        const bytes = new Uint8Array(await response.arrayBuffer());
        if (!bytes.length) continue;

        const ext = this.detectImageExtension(imageUrl, response.headers.get("content-type") || "");
        const fileName = `${safeKey}.${ext}`;
        const outputPath = `${cacheDir}/${fileName}`;
        await Deno.writeFile(outputPath, bytes);
        return `plugins/${namespace}/cache/covers/${fileName}`;
      } catch {
        continue;
      }
    }

    return "";
  }

  private detectImageExtension(url: string, contentType: string): string {
    const ct = String(contentType || "").toLowerCase();
    if (ct.includes("image/avif")) return "avif";
    if (ct.includes("image/webp")) return "webp";
    if (ct.includes("image/png")) return "png";
    if (ct.includes("image/gif")) return "gif";
    if (ct.includes("image/jpeg") || ct.includes("image/jpg")) return "jpg";

    const clean = String(url || "").split("?")[0].split("#")[0];
    const m = clean.match(/\.([a-zA-Z0-9]{2,5})$/);
    if (!m?.[1]) return "jpg";
    const ext = m[1].toLowerCase();
    if (["jpg", "jpeg", "png", "webp", "gif", "avif"].includes(ext)) {
      return ext === "jpeg" ? "jpg" : ext;
    }
    return "jpg";
  }
}

if (import.meta.main) {
  const plugin = new BofMetadataPlugin();
  await plugin.handleCommand();
}

#!/usr/bin/env deno run --allow-net --allow-read

import {
  BasePlugin,
  PluginInfo,
  PluginInput,
  PluginResult,
} from "../base_plugin.ts";

type BgmTag = {
  name?: string;
  count?: number;
};

type BgmImageSet = {
  large?: string;
  medium?: string;
  common?: string;
  small?: string;
  grid?: string;
};

type BgmSubject = {
  id: number;
  name?: string;
  name_cn?: string;
  summary?: string;
  date?: string;
  tags?: BgmTag[];
  rank?: number;
  score?: number;
  total_episodes?: number;
  images?: BgmImageSet;
  infobox?: unknown;
};

type BgmRelatedSubject = {
  id: number;
  relation?: string;
  name?: string;
  name_cn?: string;
  images?: BgmImageSet;
  image?: string;
};

type BgmSearchResult = {
  data?: BgmSubject[];
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

class BtvMetadataPlugin extends BasePlugin {
  private static readonly API_BASE = "https://api.bgm.tv";
  private static readonly WEB_BASE = "https://bangumi.tv";
  private static readonly DEFAULT_TYPE = 1;
  private static readonly USER_AGENT = "lanlu-btv-metadata/1.0";

  getPluginInfo(): PluginInfo {
    return {
      name: "Bangumi",
      type: "metadata",
      namespace: "btvmeta",
      author: "lanlu",
      version: "1.0",
      description:
        "Fetches Bangumi subject metadata and returns collection + per-volume metadata payload.",
      parameters: [
        {
          name: "access_token",
          type: "string",
          desc: "Optional Bangumi API access token (Bearer).",
        },
        {
          name: "type",
          type: "int",
          desc: "Bangumi subject type (1=book/comic).",
          default_value: "1",
        },
        {
          name: "search_limit",
          type: "int",
          desc: "Search candidate limit (1-20).",
          default_value: "8",
        },
        {
          name: "prefer_name_cn",
          type: "bool",
          desc: "Prefer Chinese title when available.",
          default_value: "1",
        },
      ],
      oneshot_arg: "Bangumi subject URL or subject id",
      cooldown: 1,
      permissions: ["net=api.bgm.tv", "net=bangumi.tv","net=lain.bgm.tv"],
      update_url:
        "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/Btv.ts",
    };
  }

  protected async runPlugin(input: PluginInput): Promise<void> {
    try {
      this.reportProgress(5, "初始化 Bangumi 元数据抓取...");
      const params = this.getParams();

      const type = this.clampInt(Number(params.type ?? BtvMetadataPlugin.DEFAULT_TYPE), 1, 6);
      const searchLimit = this.clampInt(Number(params.search_limit ?? 8), 1, 20);
      const preferNameCn = !!params.prefer_name_cn;
      const accessToken = String(params.access_token ?? "").trim();
      const subjectId =
        this.extractSubjectId(String(input.oneshotParam || "")) ||
        this.extractSubjectIdFromTags(String(input.existingTags || "")) ||
        await this.searchSubjectId(
          String(input.archiveTitle || ""),
          type,
          searchLimit,
          accessToken,
        );

      if (!subjectId) {
        this.outputResult({
          success: false,
          error:
            "No Bangumi subject id found. Provide oneshotParam (subject URL/ID), source tag, or searchable title.",
        });
        return;
      }

      this.reportProgress(25, "获取条目详情...");
      const subject = await this.fetchSubject(subjectId, accessToken);
      if (!subject) {
        this.outputResult({
          success: false,
          error: `Failed to fetch subject ${subjectId}`,
        });
        return;
      }

      this.reportProgress(50, "获取单行本关联信息...");
      const volumes = await this.fetchVolumeMetadata(subjectId, accessToken);

      this.reportProgress(85, "构建元数据输出...");
      const fetchedTags = this.buildSeriesTags(subject, type, subjectId);
      const mergedTags = fetchedTags;

      const primaryTitle = this.pickTitle(subject.name_cn, subject.name, preferNameCn) || String(subjectId);
      const summary = this.cleanSummary(subject.summary || "");
      const seriesCover = await this.cacheCoverForResult(
        this.collectCoverUrls(subject.images),
        `series_${subjectId}`,
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
            source_url: `${BtvMetadataPlugin.WEB_BASE}/subject/${subjectId}`,
          },
          archives: volumes,
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

  private async fetchVolumeMetadata(subjectId: number, accessToken: string): Promise<VolumeMeta[]> {
    const related = await this.fetchJson<BgmRelatedSubject[]>(
      `${BtvMetadataPlugin.API_BASE}/v0/subjects/${subjectId}/subjects`,
      accessToken,
    );
    if (!Array.isArray(related) || related.length === 0) {
      return [];
    }

    const volumes = related
      .filter((s) => String(s.relation || "").trim() === "单行本")
      .sort((a, b) => {
        const aNum = this.extractVolumeNo(this.pickTitle(a.name_cn, a.name, true));
        const bNum = this.extractVolumeNo(this.pickTitle(b.name_cn, b.name, true));
        if (aNum !== null && bNum !== null && aNum !== bNum) {
          return aNum - bNum;
        }
        return a.id - b.id;
      });

    const results: VolumeMeta[] = [];
    for (let i = 0; i < volumes.length; i += 1) {
      const rel = volumes[i];
      const detail = await this.fetchSubject(rel.id, accessToken);
      const detailTitle = this.pickTitle(detail?.name_cn, detail?.name, true);
      const relTitle = this.pickTitle(rel.name_cn, rel.name, true);
      const bestTitle = detailTitle || relTitle || `Volume ${i + 1}`;
      const volumeNo = this.extractVolumeNo(bestTitle) ?? (i + 1);
      const detailSummary = this.cleanSummary(detail?.summary || "");
      const isbn = this.extractInfoboxValue(detail?.infobox, ["ISBN", "isbn"]);
      const releaseDate = this.normalizeDate(this.extractInfoboxValue(detail?.infobox, ["发售日", "出版", "date"]));
      const coverUrls = this.collectCoverUrls(detail?.images, rel.images, rel.image);
      const cover = await this.cacheCoverForResult(coverUrls, `vol_${rel.id}`);

      const vTags = this.mergeCsvTags(
        this.buildVolumeTags(detail, rel.id),
        `source:${BtvMetadataPlugin.WEB_BASE}/subject/${rel.id}`,
      );

      results.push({
        volume_no: volumeNo,
        title: bestTitle,
        summary: detailSummary,
        tags: vTags,
        cover,
        release_date: releaseDate || undefined,
        isbn: isbn || undefined,
        source_url: `${BtvMetadataPlugin.WEB_BASE}/subject/${rel.id}`,
        cover_urls: coverUrls,
      });
    }

    return results;
  }

  private buildVolumeTags(subject: BgmSubject | null, subjectId: number): string {
    const tags: string[] = [];
    tags.push(`source:${BtvMetadataPlugin.WEB_BASE}/subject/${subjectId}`);
    if (!subject) return tags.join(", ");

    if (Array.isArray(subject.tags)) {
      const picked = subject.tags
        .filter((t) => !!String(t.name || "").trim())
        .sort((a, b) => Number(b.count || 0) - Number(a.count || 0))
        .slice(0, 8)
        .map((t) => String(t.name || "").trim());
      for (const t of picked) {
        tags.push(t);
      }
    }

    return this.dedupeCsv(tags.join(","));
  }

  private buildSeriesTags(subject: BgmSubject, type: number, subjectId: number): string {
    const tags: string[] = [];
    tags.push(`source:${BtvMetadataPlugin.WEB_BASE}/subject/${subjectId}`);
    tags.push(`btv:type:${type}`);

    if (Array.isArray(subject.tags)) {
      const selected = subject.tags
        .filter((t) => !!String(t.name || "").trim())
        .sort((a, b) => Number(b.count || 0) - Number(a.count || 0))
        .slice(0, 20)
        .map((t) => String(t.name || "").trim());
      tags.push(...selected);
    }

    if (typeof subject.score === "number" && Number.isFinite(subject.score) && subject.score > 0) {
      tags.push(`${Math.round(subject.score)}分`);
    }
    if (typeof subject.rank === "number" && Number.isFinite(subject.rank) && subject.rank > 0) {
      tags.push(`rank:${subject.rank}`);
    }

    return this.dedupeCsv(tags.join(","));
  }

  private async fetchSubject(subjectId: number, accessToken: string): Promise<BgmSubject | null> {
    return await this.fetchJson<BgmSubject>(
      `${BtvMetadataPlugin.API_BASE}/v0/subjects/${subjectId}`,
      accessToken,
    );
  }

  private async searchSubjectId(
    title: string,
    type: number,
    limit: number,
    accessToken: string,
  ): Promise<number | null> {
    const normalized = this.normalizeTitleForSearch(title);
    if (!normalized) return null;

    const url = `${BtvMetadataPlugin.API_BASE}/v0/search/subjects?keyword=${encodeURIComponent(normalized)}&limit=${limit}&offset=0`;
    const result = await this.fetchJson<BgmSearchResult>(url, accessToken, {
      method: "POST",
      body: JSON.stringify({
        keyword: normalized,
        sort: "match",
        filter: { type: [type] },
      }),
      headers: {
        "content-type": "application/json;charset=UTF-8",
      },
    });

    const items = result?.data;
    if (!Array.isArray(items) || items.length === 0) {
      return null;
    }

    const scored = items.map((it) => {
      const titleCn = this.normalizeTitleForSearch(it.name_cn || "");
      const titleJa = this.normalizeTitleForSearch(it.name || "");
      const score = this.titleSimilarity(normalized, titleCn || titleJa);
      return {
        id: it.id,
        score,
        title: this.pickTitle(it.name_cn, it.name, true) || `subject:${it.id}`,
        subtitle: this.pickTitle(it.name, it.name_cn, false) || "",
        date: String(it.date || "").trim(),
        cover: it.images?.common || it.images?.medium || it.images?.small || it.images?.grid || "",
      };
    });

    scored.sort((a, b) => b.score - a.score);
    if (scored.length === 1) return scored[0].id;

    const selectedIndex = await this.hostSelect(
      "Bangumi 候选匹配",
      scored.map((item) => ({
        label: item.title,
        description: [
          item.subtitle ? `原名: ${item.subtitle}` : "",
          item.date ? `日期: ${item.date}` : "",
          `匹配分: ${item.score.toFixed(2)}`,
        ]
          .filter(Boolean)
          .join(" | "),
        cover: item.cover,
      })),
      {
        message: `为“${title}”选择匹配条目`,
        defaultIndex: 0,
        timeoutSeconds: 120,
      },
    );

    return scored[selectedIndex]?.id ?? scored[0]?.id ?? null;
  }

  private async fetchJson<T>(
    url: string,
    accessToken: string,
    init?: RequestInit,
  ): Promise<T | null> {
    const headers = new Headers(init?.headers || {});
    if (!headers.has("accept")) {
      headers.set("accept", "application/json");
    }
    headers.set("user-agent", BtvMetadataPlugin.USER_AGENT);
    if (accessToken) {
      headers.set("authorization", `Bearer ${accessToken}`);
    }

    const response = await fetch(url, {
      method: init?.method || "GET",
      body: init?.body,
      headers,
    });

    if (!response.ok) {
      return null;
    }

    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      return null;
    }

    try {
      return (await response.json()) as T;
    } catch {
      return null;
    }
  }

  private collectCoverUrls(...sets: Array<BgmImageSet | string | undefined>): string[] {
    const urls: string[] = [];
    for (const item of sets) {
      if (!item) continue;
      if (typeof item === "string") {
        if (item.trim()) urls.push(item.trim());
        continue;
      }
      if (item.large) urls.push(item.large);
      if (item.medium) urls.push(item.medium);
      if (item.common) urls.push(item.common);
      if (item.small) urls.push(item.small);
      if (item.grid) urls.push(item.grid);
    }
    return Array.from(new Set(urls.filter(Boolean)));
  }

  private extractSubjectId(value: string): number | null {
    const raw = value.trim();
    if (!raw) return null;

    if (/^\d+$/.test(raw)) {
      const id = Number(raw);
      return Number.isFinite(id) && id > 0 ? id : null;
    }

    const m = raw.match(/\/subject\/(\d+)/i);
    if (m?.[1]) {
      const id = Number(m[1]);
      return Number.isFinite(id) && id > 0 ? id : null;
    }

    return null;
  }

  private extractSubjectIdFromTags(existingTags: string): number | null {
    if (!existingTags) return null;
    const m = existingTags.match(/source:\s*https?:\/\/[^\s,]*bangumi\.tv\/subject\/(\d+)/i);
    if (m?.[1]) {
      const id = Number(m[1]);
      return Number.isFinite(id) && id > 0 ? id : null;
    }
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

  private pickTitle(nameCn?: string, name?: string, preferCn = true): string {
    const cn = String(nameCn || "").trim();
    const jp = String(name || "").trim();
    if (preferCn) return cn || jp;
    return jp || cn;
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

  private extractInfoboxValue(infobox: unknown, keys: string[]): string {
    if (!Array.isArray(infobox)) return "";
    const lowered = keys.map((k) => k.toLowerCase());

    for (const row of infobox) {
      if (!row || typeof row !== "object") continue;
      const key = String((row as Record<string, unknown>).key || "").trim();
      if (!key) continue;
      if (!lowered.includes(key.toLowerCase())) continue;

      const value = (row as Record<string, unknown>).value;
      if (typeof value === "string") return value.trim();
      if (Array.isArray(value)) {
        const merged = value
          .map((v) => {
            if (typeof v === "string") return v;
            if (v && typeof v === "object") {
              const o = v as Record<string, unknown>;
              return String(o.v ?? o.k ?? "");
            }
            return "";
          })
          .filter(Boolean)
          .join(" ")
          .trim();
        if (merged) return merged;
      }
      if (value !== null && value !== undefined) {
        return String(value).trim();
      }
    }

    return "";
  }

  private normalizeDate(input: string): string {
    const s = String(input || "").trim();
    if (!s) return "";

    const direct = s.match(/^(\d{4})[-/年](\d{1,2})[-/月](\d{1,2})/);
    if (direct) {
      return `${direct[1]}-${direct[2].padStart(2, "0")}-${direct[3].padStart(2, "0")}`;
    }

    const ym = s.match(/^(\d{4})[-/年](\d{1,2})/);
    if (ym) {
      return `${ym[1]}-${ym[2].padStart(2, "0")}-01`;
    }

    const asDate = Date.parse(s);
    if (Number.isFinite(asDate)) {
      const d = new Date(asDate);
      const y = d.getUTCFullYear();
      const m = String(d.getUTCMonth() + 1).padStart(2, "0");
      const day = String(d.getUTCDate()).padStart(2, "0");
      return `${y}-${m}-${day}`;
    }
    return "";
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
    const namespace = String(this.getPluginInfo().namespace || "btvmeta").trim();
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
            "user-agent": BtvMetadataPlugin.USER_AGENT,
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
  const plugin = new BtvMetadataPlugin();
  await plugin.handleCommand();
}

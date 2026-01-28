#!/usr/bin/env deno run --allow-net --allow-read

import { BasePlugin, PluginInfo, PluginInput, PluginResult } from "../base_plugin.ts";

/**
 * nHentai 元数据插件
 * - 支持 oneshotParam 直接传入 gallery URL 或数字 ID
 * - 否则尝试从 existingTags 的 source:nhentai.net/g/<id> 中提取
 * - 否则从标题中提取 {123456}，再不行就用 nhentai 搜索第一页第一个结果兜底
 */
class NHentaiMetadataPlugin extends BasePlugin {
  private static readonly USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

  private loginCookies = "";

  getPluginInfo(): PluginInfo {
    return {
      name: "nHentai",
      type: "metadata",
      namespace: "nhplugin",
      login_from: "nhlogin",
      author: "Difegue and others (ported)",
      version: "1.1",
      description:
        "Searches nHentai for tags matching your archive. Supports reading the ID from titles formatted as \"{Id} Title\" and otherwise searches by title. Uses the source: tag if present.",
      parameters: [
        {
          // Keep naming consistent with EHentai.ts, which uses `updated_at:` to map to archives.updated_at.
          name: "additionaltags",
          type: "bool",
          desc: "Fetch upload_date and set updated_at:<epoch> tag",
          default_value: "0",
        },
      ],
      oneshot_arg:
        "nHentai Gallery URL or ID (Will attach tags matching this exact gallery to your archive)",
      cooldown: 2,
      permissions: ["net=nhentai.net"],
      update_url: "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/NHentai.ts",
    };
  }

  protected async runPlugin(input: PluginInput): Promise<void> {
    try {
      this.reportProgress(5, "初始化 nHentai 元数据抓取...");
      const params = this.getParams();
      // Accept legacy param name `add_uploaded` (older plugin versions) in addition to `additionaltags`.
      const addUploaded = this.coerceBoolLike((params as any).additionaltags ?? (params as any).add_uploaded);

      this.loginCookies = this.buildCookieString(
        (input.loginCookies || []) as Array<{ name: string; value: string; domain?: string; path?: string }>,
      );

      const oneshot = String(input.oneshotParam || "").trim();
      const existingTags = String(input.existingTags || "");
      const title = String(input.archiveTitle || "").trim();

      const galleryId =
        this.extractGalleryId(oneshot) ||
        this.extractGalleryIdFromSourceTag(existingTags) ||
        this.extractGalleryIdFromTitle(title) ||
        (title ? await this.searchGalleryIdByTitle(title) : null);

      if (!galleryId) {
        this.outputResult({ success: false, error: "No matching nHentai Gallery Found!" });
        return;
      }

      this.reportProgress(30, `获取画廊 ${galleryId} 元数据...`);
      const result = await this.fetchGalleryMetadata(galleryId, addUploaded);
      this.reportProgress(100, "元数据获取完成");
      this.outputResult(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.outputResult({ success: false, error: `Plugin execution failed: ${errorMessage}` });
    }
  }

  private buildCookieString(
    cookies: Array<{ name: string; value: string; domain?: string; path?: string }>,
  ): string {
    return cookies
      .filter((c) => {
        const d = String(c?.domain || "").trim().toLowerCase();
        // If domain is missing, keep it (some backends might omit it).
        if (!d) return true;
        return d === "nhentai.net" || d.endsWith(".nhentai.net");
      })
      .filter((c) => c?.name && c?.value)
      .map((c) => `${String(c.name)}=${String(c.value)}`)
      .join("; ");
  }

  private defaultHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      "User-Agent": NHentaiMetadataPlugin.USER_AGENT,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Referer": "https://nhentai.net/",
      "Connection": "keep-alive",
    };
    if (this.loginCookies) headers["Cookie"] = this.loginCookies;
    return headers;
  }

  private extractGalleryId(input: string): string | null {
    const clean = input.replace(/^["'\s]+|["'\s]+$/g, "").trim();
    if (!clean) return null;
    if (/^\d+$/.test(clean)) return clean;
    const m = clean.match(/nhentai\.net\/g\/(\d+)/i);
    return m?.[1] || null;
  }

  private extractGalleryIdFromSourceTag(existingTags: string): string | null {
    // Match tags like: source:nhentai.net/g/123 or source:https://nhentai.net/g/123/
    const m = existingTags.match(/source:\s*(?:https?:\/\/)?nhentai\.net\/g\/(\d+)/i);
    if (m) return m[1];
    const m2 = existingTags.match(/source:\s*nhentai\.net\/g\/(\d+)/i);
    if (m2) return m2[1];
    return null;
  }

  private extractGalleryIdFromTitle(title: string): string | null {
    const m = title.match(/\{(\d+)\}/);
    return m?.[1] || null;
  }

  private sanitizeSearchTitle(title: string): string {
    // Keep behavior close to the Perl plugin: hyphens and apostrophes can break nh search.
    return title.replace(/[-']/g, " ").trim();
  }

  private async searchGalleryIdByTitle(title: string): Promise<string | null> {
    const q = this.sanitizeSearchTitle(title);
    if (!q) return null;

    const url = `https://nhentai.net/search/?q=${encodeURIComponent(q)}`;
    const resp = await fetch(url, { headers: this.defaultHeaders() });

    if (!resp.ok) {
      return null;
    }

    const html = await resp.text();
    if (this.looksLikeCloudflareBlock(html)) {
      throw new Error("Cloudflare protection detected. Please configure nhlogin cookies (cf_clearance).");
    }

    // Grab the first cover link: <a class="cover" href="/g/123456/">
    const coverHref =
      html.match(/class="cover"[^>]*href="([^"]+)"/i)?.[1] ||
      html.match(/<a[^>]+href="(\/g\/\d+\/)"/i)?.[1] ||
      "";
    const id = coverHref.match(/\/g\/(\d+)\//)?.[1];
    return id || null;
  }

  private looksLikeCloudflareBlock(html: string): boolean {
    const h = html.toLowerCase();
    return h.includes("just a moment") || h.includes("checking your browser") || h.includes("cf-browser-verification");
  }

  private extractGalleryJsonFromHtml(html: string): any | null {
    // Page embeds: window._gallery = JSON.parse("..."); where the argument itself is a JSON string.
    const m = html.match(
      /window\._gallery\s*=\s*JSON\.parse\(\s*(\"(?:\\.|[^\"\\])*\")\s*\)\s*;/s,
    );
    if (!m) return null;
    const jsonString = JSON.parse(m[1]); // decodes \uXXXX escapes into real characters, returns string
    return JSON.parse(jsonString);
  }

  private buildTagsFromGalleryJson(gallery: any, galleryId: string, addUploaded: boolean): string {
    const tags: string[] = [];
    const jsonTags: any[] = Array.isArray(gallery?.tags) ? gallery.tags : [];

    for (const t of jsonTags) {
      const ns = String(t?.type || "").trim();
      const name = String(t?.name || "").trim();
      if (!name) continue;
      if (ns === "tag" || !ns) tags.push(name);
      else tags.push(`${ns}:${name}`);
    }

    if (addUploaded) {
      const uploadDate = gallery?.upload_date;
      if (typeof uploadDate === "number" && Number.isFinite(uploadDate)) {
        // Use updated_at namespace so the backend can map it to archives.updated_at (see EHentai.ts).
        tags.push(`updated_at:${Math.trunc(uploadDate)}`);
      } else if (typeof uploadDate === "string" && uploadDate.trim()) {
        tags.push(`updated_at:${uploadDate.trim()}`);
      }
    }

    if (tags.length > 0) {
      tags.push(`source:nhentai.net/g/${galleryId}`);
    }

    return tags.join(", ");
  }

  private coerceBoolLike(value: unknown): boolean {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value !== 0;
    if (typeof value === "string") {
      const v = value.trim().toLowerCase();
      if (v === "" || v === "0" || v === "false" || v === "no" || v === "n" || v === "off") return false;
      if (v === "1" || v === "true" || v === "yes" || v === "y" || v === "on") return true;
      return v !== "0";
    }
    return Boolean(value);
  }

  private pickTitleFromGalleryJson(gallery: any, galleryId: string): string {
    const pretty = String(gallery?.title?.pretty || "").trim();
    if (pretty) return pretty;
    const en = String(gallery?.title?.english || "").trim();
    if (en) return en;
    const jp = String(gallery?.title?.japanese || "").trim();
    if (jp) return jp;
    return `Gallery ${galleryId}`;
  }

  private async fetchGalleryMetadata(galleryId: string, addUploaded: boolean): Promise<PluginResult> {
    const url = `https://nhentai.net/g/${galleryId}/`;
    const resp = await fetch(url, { headers: this.defaultHeaders() });

    if (resp.status === 404) return { success: false, error: `Gallery not found: ${galleryId}` };
    if (resp.status === 403) {
      return {
        success: false,
        error: "Blocked by Cloudflare. Please configure nhlogin cookies (cf_clearance) and retry.",
      };
    }
    if (!resp.ok) return { success: false, error: `Failed to fetch gallery: HTTP ${resp.status}` };

    const html = await resp.text();
    if (this.looksLikeCloudflareBlock(html)) {
      return {
        success: false,
        error: "Cloudflare protection detected. Please configure nhlogin cookies (cf_clearance) and retry.",
      };
    }

    const gallery = this.extractGalleryJsonFromHtml(html);
    if (!gallery) return { success: false, error: "Failed to parse gallery metadata (missing embedded JSON)" };

    const tags = this.buildTagsFromGalleryJson(gallery, galleryId, addUploaded);
    const title = this.pickTitleFromGalleryJson(gallery, galleryId);

    return {
      success: true,
      data: {
        tags,
        title,
      },
    };
  }
}

if (import.meta.main) {
  const plugin = new NHentaiMetadataPlugin();
  await plugin.handleCommand();
}

#!/usr/bin/env deno run --allow-net --allow-read --allow-write

import { BasePlugin, PluginInfo, PluginInput, PluginResult } from "../base_plugin.ts";
import { TwitterOpenApi } from "npm:twitter-openapi-typescript";

/**
 * Twitter/X 下载插件
 * - 支持 tweet/status 链接下载图片/视频
 * - 默认使用 guest client（无需登录），若提供 login cookies 则自动切换到登录态
 *
 * 依赖说明：
 * - 使用 twitter-openapi-typescript 来稳定提取媒体链接（避免解析页面 HTML）。
 */

type LoginCookie = { name: string; value: string; domain: string; path: string };

type XMedia = {
  type?: string;
  mediaUrlHttps?: string;
  videoInfo?: {
    variants?: Array<{ bitrate?: number; contentType?: string; url?: string }>;
  };
};

class TwitterDownloadPlugin extends BasePlugin {
  private static readonly USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

  getPluginInfo(): PluginInfo {
    return {
      name: "Twitter/X Downloader",
      type: "download",
      namespace: "xdl",
      login_from: "xlogin",
      author: "copur",
      version: "1.0",
      description: "Downloads media (photos/videos) from a single X (Twitter) post URL.",
      parameters: [
        {
          name: "image_quality",
          type: "string",
          desc: "Photo quality for pbs.twimg.com: orig | large | medium | small | 4096x4096 | 1200x1200 | 900x900",
          default_value: "orig",
        },
      ],
      url_regex: "https?://(x\\.com|twitter\\.com)/(?:[^/]+/status/\\d+|i/web/status/\\d+)(?:\\?.*)?$",
      permissions: [
        "net=x.com",
        "net=twitter.com",
        "net=pbs.twimg.com",
        "net=video.twimg.com",
        "net=abs.twimg.com",
        "net=registry.npmjs.org",
        "net=raw.githubusercontent.com",
      ],
      update_url: "https://git.copur.xyz/copur/lanlup/raw/branch/master/Download/Twitter.ts",
    };
  }

  protected async runPlugin(input: PluginInput): Promise<void> {
    try {
      const url = (input.url || "").trim();
      if (!url) {
        this.outputResult({ success: false, error: "No URL provided." });
        return;
      }

      const params = this.getParams();
      const quality = String(params.image_quality || "orig").trim() || "orig";

      const result = await this.downloadTweet(url, {
        quality,
        loginCookies: (input.loginCookies || []) as LoginCookie[],
      });
      this.outputResult(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.outputResult({ success: false, error: `Plugin execution failed: ${errorMessage}` });
    }
  }

  private extractTweetId(url: string): string | null {
    // common formats:
    // - https://x.com/user/status/123
    // - https://twitter.com/user/status/123
    // - https://x.com/i/web/status/123
    const m = url.match(/\/status\/(\d+)/) || url.match(/\/i\/web\/status\/(\d+)/);
    return m?.[1] || null;
  }

  private extractScreenName(url: string): string | null {
    const m = url.match(/https?:\/\/(?:x\.com|twitter\.com)\/([^\/]+)\/status\/\d+/);
    return m?.[1] || null;
  }

  private cookiesToObject(cookies: LoginCookie[]): Record<string, string> {
    const allowDomain = (d: string) =>
      d === "x.com" ||
      d.endsWith(".x.com") ||
      d === "twitter.com" ||
      d.endsWith(".twitter.com");

    const obj: Record<string, string> = {};
    for (const c of cookies) {
      if (!c?.name || !c?.value) continue;
      if (!c?.domain || !allowDomain(String(c.domain))) continue;
      obj[String(c.name)] = String(c.value);
    }
    return obj;
  }

  private async getClientFromInput(loginCookies: LoginCookie[]) {
    const api = new TwitterOpenApi();
    const cookieObj = this.cookiesToObject(loginCookies);
    // Prefer login session if available (protected posts, higher rate-limits, etc.)
    if (cookieObj.auth_token) {
      return await api.getClientFromCookies(cookieObj);
    }
    return await api.getGuestClient();
  }

  private pickBestMp4(variants: Array<{ bitrate?: number; contentType?: string; url?: string }>): string | null {
    const mp4s = variants
      .filter((v) => v && v.contentType === "video/mp4" && typeof v.url === "string" && v.url.length > 0)
      .sort((a, b) => (b.bitrate || 0) - (a.bitrate || 0));
    return mp4s[0]?.url || null;
  }

  private photoUrlWithQuality(url: string, quality: string): string {
    try {
      const u = new URL(url);
      if (u.hostname !== "pbs.twimg.com") return url;
      if (!u.pathname.includes("/media/")) return url;

      const seg = u.pathname.split("/").pop() || "";
      const dot = seg.lastIndexOf(".");
      const id = dot > 0 ? seg.slice(0, dot) : seg;
      const ext = dot > 0 ? seg.slice(dot + 1).toLowerCase() : (u.searchParams.get("format") || "jpg");
      const fmt = ext === "jpeg" ? "jpg" : ext;

      // Keep only safe values; default to orig
      const name = quality || "orig";
      return `https://pbs.twimg.com/media/${id}?format=${encodeURIComponent(fmt)}&name=${encodeURIComponent(name)}`;
    } catch {
      return url;
    }
  }

  private guessExtFromUrl(url: string): string {
    try {
      const u = new URL(url);
      // Prefer explicit format query for pbs.twimg.com
      const fmt = u.searchParams.get("format");
      if (fmt) return fmt.toLowerCase() === "jpeg" ? "jpg" : fmt.toLowerCase();
      const base = u.pathname.split("/").pop() || "";
      const dot = base.lastIndexOf(".");
      if (dot > 0) {
        const ext = base.slice(dot + 1).toLowerCase();
        return ext === "jpeg" ? "jpg" : ext;
      }
    } catch {
      // ignore
    }
    return "bin";
  }

  private sanitizeFilename(name: string): string {
    return String(name)
      .replace(/[<>:"/\\|?*\[\]「」]/g, "")
      .trim()
      .substring(0, 120);
  }

  private async downloadToFile(url: string, filePath: string, referer: string): Promise<boolean> {
    try {
      const resp = await fetch(url, {
        headers: {
          "User-Agent": TwitterDownloadPlugin.USER_AGENT,
          "Accept": "*/*",
          "Referer": referer,
        },
      });
      if (!resp.ok || !resp.body) {
        await this.logWarn("download:failed", { url, status: resp.status });
        return false;
      }

      const file = await Deno.open(filePath, { create: true, write: true, truncate: true });
      try {
        const reader = resp.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value || value.length === 0) continue;
          let offset = 0;
          while (offset < value.length) {
            const n = await file.write(value.subarray(offset));
            if (n <= 0) break;
            offset += n;
          }
        }
      } finally {
        try {
          file.close();
        } catch {
          // ignore
        }
      }
      return true;
    } catch (error) {
      await this.logError("download:error", { url, error: String(error) });
      return false;
    }
  }

  private async downloadTweet(
    tweetUrl: string,
    opts: { quality: string; loginCookies: LoginCookie[] },
  ): Promise<PluginResult> {
    const tweetId = this.extractTweetId(tweetUrl);
    if (!tweetId) {
      return { success: false, error: "Invalid X/Twitter status URL." };
    }

    this.reportProgress(1, "Fetching tweet info...");
    await this.logInfo("tweet:fetch", { tweetId, tweetUrl });

    const client = await this.getClientFromInput(opts.loginCookies);

    let tweetResult: any;
    try {
      // NOTE: TweetDetail frequently breaks due to queryId churn; TweetResultByRestId tends to be more stable.
      const resp: any = await client.getDefaultApi().getTweetResultByRestId({ tweetId });
      tweetResult = resp?.data;
    } catch (error) {
      const status = (error as any)?.response?.status;
      const url = (error as any)?.response?.url;
      const msg = error instanceof Error ? error.message : String(error);
      const parts = [
        status ? `Failed to fetch tweet metadata (HTTP ${status}).` : "Failed to fetch tweet metadata.",
        msg,
        url ? `URL: ${url}` : "",
      ].filter(Boolean);
      return { success: false, error: parts.join(" ") };
    }

    const screenNameFromUrl = this.extractScreenName(tweetUrl);
    const authorSn =
      tweetResult?.user?.legacy?.screenName ||
      tweetResult?.user?.legacy?.screen_name ||
      screenNameFromUrl ||
      "unknown";

    const media: XMedia[] = tweetResult?.tweet?.legacy?.extendedEntities?.media || [];
    if (!Array.isArray(media) || media.length === 0) {
      return { success: false, error: "No media found in this tweet (or it is not accessible)." };
    }

    // Keep consistent with other download plugins:
    // - files go under `./data/cache/plugins/<namespace>/...`
    // - we return `plugins/<namespace>/...` as `relative_path`
    const baseDir = this.input?.pluginDir || "./data/cache/plugins/xdl";
    const relDir = `plugins/xdl/${this.sanitizeFilename(authorSn)}/${tweetId}`;
    const absDir = `${baseDir}/${this.sanitizeFilename(authorSn)}/${tweetId}`;
    await Deno.mkdir(absDir, { recursive: true });

    let okCount = 0;
    let failCount = 0;
    let idx = 0;

    for (const m of media) {
      idx++;
      const type = String(m?.type || "");

      let url: string | null = null;
      let prefix = "file";

      if (type === "photo") {
        prefix = "photo";
        url = typeof m.mediaUrlHttps === "string" ? m.mediaUrlHttps : null;
        if (url) url = this.photoUrlWithQuality(url, opts.quality);
      } else if (type === "video" || type === "animated_gif") {
        prefix = type === "animated_gif" ? "gif" : "video";
        const variants = m?.videoInfo?.variants || [];
        url = this.pickBestMp4(Array.isArray(variants) ? variants : []);
      }

      if (!url) {
        failCount++;
        await this.logWarn("media:skip", { tweetId, type });
        continue;
      }

      const ext = this.guessExtFromUrl(url);
      const filename = `${tweetId}_${prefix}_${String(idx).padStart(2, "0")}.${ext}`;
      const filePath = `${absDir}/${filename}`;

      const progress = Math.round((idx / media.length) * 100);
      this.reportProgress(progress, `Downloading ${prefix} ${idx}/${media.length}...`);

      const ok = await this.downloadToFile(url, filePath, tweetUrl);
      if (ok) okCount++;
      else failCount++;
    }

    this.reportProgress(100, `Done. Downloaded: ${okCount}, failed: ${failCount}`);
    if (okCount === 0) {
      return { success: false, error: "All downloads failed." };
    }

    return {
      success: true,
      data: [
        {
          relative_path: relDir,
          filename: `${this.sanitizeFilename(authorSn)}_${tweetId}`,
          source: tweetUrl,
          downloaded_count: okCount,
          failed_count: failCount,
        },
      ],
    };
  }
}

if (import.meta.main) {
  const plugin = new TwitterDownloadPlugin();
  await plugin.handleCommand();
}

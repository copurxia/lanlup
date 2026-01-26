#!/usr/bin/env deno run --allow-net --allow-read

import { BasePlugin, PluginInfo, PluginInput, PluginResult } from "../base_plugin.ts";
import { TwitterOpenApi } from "npm:twitter-openapi-typescript";

/**
 * Twitter/X 元数据插件
 * - 支持 X/Twitter status URL 或 tweetId
 * - 将推文内容写入 description
 */

type LoginCookie = { name: string; value: string; domain?: string; path?: string };

class TwitterMetadataPlugin extends BasePlugin {
  getPluginInfo(): PluginInfo {
    return {
      name: "Twitter/X",
      type: "metadata",
      namespace: "xmeta",
      login_from: "xlogin",
      author: "copur",
      version: "1.0",
      description: "Fetches tweet text as description and adds basic source/author tags.",
      parameters: [
        { name: "merge_existing", type: "bool", desc: "Merge new tags with existing archive tags", default_value: "1" },
        { name: "prefix_id", type: "bool", desc: "Prefix title with tweetId", default_value: "0" },
        { name: "strip_newlines", type: "bool", desc: "Replace newlines with spaces in description", default_value: "0" },
      ],
      oneshot_arg: "X/Twitter status URL or tweetId",
      cooldown: 1,
      permissions: [
        "net=x.com",
        "net=twitter.com",
        "net=abs.twimg.com",
        "net=registry.npmjs.org",
        "net=raw.githubusercontent.com",
      ],
      update_url: "https://git.copur.xyz/copur/lanlu/raw/branch/main/plugins/Metadata/Twitter.ts",
    };
  }

  protected async runPlugin(input: PluginInput): Promise<void> {
    try {
      this.reportProgress(5, "Initializing X metadata...");
      const params = this.getParams();
      const mergeExisting = !!params.merge_existing;
      const prefixId = !!params.prefix_id;
      const stripNewlines = !!params.strip_newlines;

      const oneshot = String(input.oneshotParam || "").trim();
      const existingTags = String(input.existingTags || "");

      const tweetId =
        this.extractTweetId(oneshot) ||
        this.extractTweetIdFromSourceTag(existingTags) ||
        this.extractTweetIdFromTitle(String(input.archiveTitle || ""));

      if (!tweetId) {
        this.outputResult({
          success: false,
          error:
            "No tweetId found. Provide oneshotParam as X/Twitter status URL/ID, or add a source:https://x.com/<user>/status/<id> tag.",
        });
        return;
      }

      const client = await this.getClientFromInput((input.loginCookies || []) as LoginCookie[]);
      this.reportProgress(30, "Fetching tweet metadata...");

      let tweetResult: any;
      try {
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
        this.outputResult({ success: false, error: parts.join(" ") });
        return;
      }

      const userLegacy = tweetResult?.user?.legacy || {};
      const tweetLegacy = tweetResult?.tweet?.legacy || {};

      const screenName = String(userLegacy.screenName || userLegacy.screen_name || "").trim() || "unknown";
      const displayName = String(userLegacy.name || "").trim();
      const tweetUrl = `https://x.com/${encodeURIComponent(screenName)}/status/${tweetId}`;

      const textRaw = this.pickTweetText(tweetResult);
      const textExpanded = this.expandUrls(textRaw, tweetLegacy?.entities);
      const description = stripNewlines ? textExpanded.replace(/\s*\n+\s*/g, " ").trim() : textExpanded.trim();

      const baseTitle = [displayName || screenName, tweetId].filter(Boolean).join(" ");
      const title = prefixId ? `${tweetId} ${displayName || screenName}`.trim() : baseTitle;

      const createdAt = this.normalizeToEpochSeconds(tweetLegacy?.createdAt);
      const tags = this.buildTags(tweetId, tweetUrl, screenName, displayName, createdAt);
      const merged = mergeExisting ? this.mergeTags(existingTags, tags) : tags;

      this.reportProgress(100, "Metadata fetched");
      this.outputResult({
        success: true,
        data: {
          title,
          summary: description,
          tags: merged,
        },
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.outputResult({ success: false, error: `Plugin execution failed: ${errorMessage}` });
    }
  }

  private extractTweetId(input: string): string | null {
    const clean = input.replace(/^["'\s]+|["'\s]+$/g, "").trim();
    if (!clean) return null;
    if (/^\d+$/.test(clean)) return clean;
    const m = clean.match(/\/status\/(\d+)/) || clean.match(/\/i\/web\/status\/(\d+)/);
    return m?.[1] || null;
  }

  private extractTweetIdFromSourceTag(existingTags: string): string | null {
    // Match tags like: source:https://x.com/user/status/123
    const m = existingTags.match(/source:\s*https?:\/\/(?:x\.com|twitter\.com)\/[^,\s]+/i);
    if (!m) return null;
    return this.extractTweetId(m[0].replace(/^source:\s*/i, ""));
  }

  private extractTweetIdFromTitle(title: string): string | null {
    const m = title.match(/\b(\d{10,})\b/);
    return m?.[1] || null;
  }

  private cookiesToObject(cookies: LoginCookie[]): Record<string, string> {
    const allowDomain = (d: string) =>
      d === "x.com" || d.endsWith(".x.com") || d === "twitter.com" || d.endsWith(".twitter.com");

    const obj: Record<string, string> = {};
    for (const c of cookies) {
      if (!c?.name || !c?.value) continue;
      if (c?.domain && !allowDomain(String(c.domain))) continue;
      obj[String(c.name)] = String(c.value);
    }
    return obj;
  }

  private async getClientFromInput(loginCookies: LoginCookie[]) {
    const api = new TwitterOpenApi();
    const cookieObj = this.cookiesToObject(loginCookies);
    if (cookieObj.auth_token) {
      return await api.getClientFromCookies(cookieObj);
    }
    return await api.getGuestClient();
  }

  private pickTweetText(tweetResult: any): string {
    // Prefer noteTweet for long posts if available; fall back to legacy fullText.
    try {
      const note =
        tweetResult?.tweet?.noteTweet?.noteTweetResults?.result?.text ||
        tweetResult?.tweet?.noteTweet?.noteTweetResults?.result?.entitySet?.rawText;
      if (typeof note === "string" && note.trim()) return note;
    } catch {
      // ignore
    }
    const legacy = tweetResult?.tweet?.legacy;
    const full = legacy?.fullText || legacy?.full_text;
    return typeof full === "string" ? full : "";
  }

  private expandUrls(text: string, entities: any): string {
    if (!text) return "";
    const urls: Array<{ url?: string; expanded_url?: string; expandedUrl?: string }> = entities?.urls || [];
    let out = text;
    for (const u of urls) {
      const short = String(u?.url || "").trim();
      const expanded = String(u?.expandedUrl || u?.expanded_url || "").trim();
      if (!short || !expanded) continue;
      out = out.split(short).join(expanded);
    }
    return out;
  }

  private normalizeToEpochSeconds(value: unknown): string | null {
    if (value === null || value === undefined) return null;
    if (typeof value === "number" && Number.isFinite(value)) {
      return value > 1_000_000_000_000 ? String(Math.floor(value / 1000)) : String(Math.floor(value));
    }
    const s = String(value).trim();
    if (!s) return null;
    if (/^\d+$/.test(s)) {
      try {
        const n = BigInt(s);
        if (n > 1_000_000_000_000n) return String(n / 1000n);
        return String(n);
      } catch {
        return null;
      }
    }
    const ms = Date.parse(s);
    if (Number.isFinite(ms)) return String(Math.floor(ms / 1000));
    return null;
  }

  private buildTags(
    tweetId: string,
    tweetUrl: string,
    screenName: string,
    displayName: string,
    createdAt: string | null,
  ): string {
    const out: string[] = [];
    out.push(`source:${tweetUrl}`);
    out.push(`x:${tweetId}`);
    if (screenName) out.push(`x_user:${screenName}`);
    // User requirement: store author username as artist:{id}
    if (screenName) out.push(`artist:${screenName}`);
    if (displayName) out.push(`x_name:${displayName}`);
    if (createdAt) out.push(`updated_at:${createdAt}`);

    const seen = new Set<string>();
    const deduped: string[] = [];
    for (const t of out) {
      const k = t.trim();
      if (!k) continue;
      if (seen.has(k)) continue;
      seen.add(k);
      deduped.push(k);
    }
    return deduped.join(", ");
  }

  private mergeTags(existing: string, additions: string): string {
    const list = (s: string) =>
      s
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t.length > 0);

    const out: string[] = [];
    const seen = new Set<string>();

    for (const t of [...list(existing), ...list(additions)]) {
      if (seen.has(t)) continue;
      seen.add(t);
      out.push(t);
    }

    return out.join(", ");
  }
}

if (import.meta.main) {
  const plugin = new TwitterMetadataPlugin();
  await plugin.handleCommand();
}

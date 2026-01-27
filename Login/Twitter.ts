#!/usr/bin/env deno run --allow-net --allow-read

import { BasePlugin, PluginInfo, PluginInput, PluginResult } from "../base_plugin.ts";

/**
 * Twitter/X 登录插件
 *
 * 目前下载插件默认使用 guest client（无需登录）。
 * 若要访问受限内容/降低风控，可在此保存 auth_token（并自动尝试获取 ct0）。
 */

type StoredCookie = { name: string; value: string; domain: string; path: string };

class TwitterLoginPlugin extends BasePlugin {
  private static readonly USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

  getPluginInfo(): PluginInfo {
    return {
      name: "Twitter/X",
      type: "login",
      namespace: "xlogin",
      author: "copur",
      version: "1.0",
      description:
        "Stores X (Twitter) auth cookies for other X plugins. Provide `auth_token` (required). `ct0` is optional (will be derived if possible).",
      parameters: [
        { name: "auth_token", type: "string", desc: "X auth_token cookie value (from your browser after login)" },
        { name: "ct0", type: "string", desc: "Optional csrf token cookie (ct0). Leave blank to auto-derive." },
      ],
      permissions: ["net=x.com"],
      update_url: "https://git.copur.xyz/copur/lanlup/raw/branch/master/Login/Twitter.ts",
    };
  }

  protected async runPlugin(_: PluginInput): Promise<void> {
    try {
      this.reportProgress(10, "Reading login params...");
      const params = this.getParams();
      const authToken = String(params.auth_token || "").trim();
      let ct0 = String(params.ct0 || "").trim();

      const result = await this.doLogin(authToken, ct0);
      this.reportProgress(100, "Login configured");
      this.outputResult(result);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.outputResult({ success: false, error: `Plugin execution failed: ${errorMessage}` });
    }
  }

  private parseSetCookies(setCookies: string[]): Record<string, string> {
    const obj: Record<string, string> = {};
    for (const sc of setCookies) {
      const first = String(sc).split(";")[0];
      const eq = first.indexOf("=");
      if (eq <= 0) continue;
      const name = first.slice(0, eq).trim();
      const value = first.slice(eq + 1).trim();
      if (!name) continue;
      obj[name] = value;
    }
    return obj;
  }

  private async deriveCt0(authToken: string): Promise<string | null> {
    try {
      const resp = await fetch("https://x.com/manifest.json", {
        headers: {
          "User-Agent": TwitterLoginPlugin.USER_AGENT,
          "Accept": "application/json, text/plain, */*",
          "Referer": "https://x.com/",
          "Cookie": `auth_token=${authToken}`,
        },
      });

      const getSetCookie = (resp.headers as any).getSetCookie?.bind(resp.headers);
      const setCookies: string[] = (typeof getSetCookie === "function" ? getSetCookie() : []) as string[];
      const fallback = resp.headers.get("set-cookie");
      if (setCookies.length === 0 && fallback) setCookies.push(fallback);

      const cookieObj = this.parseSetCookies(setCookies);
      return cookieObj.ct0 || null;
    } catch {
      return null;
    }
  }

  private async doLogin(authToken: string, ct0: string): Promise<PluginResult> {
    if (!authToken) {
      // Keep consistent with other login plugins: allow blank config.
      return { success: true, data: { cookies: [], message: "No cookies provided, returning blank configuration." } };
    }

    if (!ct0) {
      this.reportProgress(30, "Trying to derive ct0...");
      const derived = await this.deriveCt0(authToken);
      if (derived) ct0 = derived;
    }

    const cookies: StoredCookie[] = [{ name: "auth_token", value: authToken, domain: "x.com", path: "/" }];
    if (ct0) cookies.push({ name: "ct0", value: ct0, domain: "x.com", path: "/" });

    const msg = ct0
      ? "Successfully configured X authentication cookies (auth_token + ct0)."
      : "Configured auth_token, but ct0 is missing (some endpoints may fail). You can re-run login plugin or provide ct0 manually.";

    return { success: true, data: { cookies, message: msg } };
  }
}

if (import.meta.main) {
  const plugin = new TwitterLoginPlugin();
  await plugin.handleCommand();
}


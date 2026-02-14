#!/usr/bin/env deno run --allow-net --allow-read

import {
  BasePlugin,
  PluginInfo,
  PluginInput,
  PluginResult,
} from "../base_plugin.ts";

type EhGalleryCandidate = {
  gID: string;
  gToken: string;
  title: string;
  url: string;
  cover?: string;
};

type TankoubonArchivesResponse = {
  archiveIds?: string[];
};

type ArchiveMetadataResponse = {
  archiveId?: string;
  title?: string;
  existingTags?: string;
  thumbnailHash?: string;
};

/**
 * E-Hentai元数据插件
 * 从E-Hentai搜索并获取画廊标签和元数据
 */
class EHentaiMetadataPlugin extends BasePlugin {
  private static readonly USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";

  getPluginInfo(): PluginInfo {
    return {
      name: "E-Hentai",
      type: "metadata",
      namespace: "ehplugin",
      login_from: "ehlogin",
      author: "Difegue and others",
      version: "2.6",
      description:
        "Searches g.e-hentai for tags matching your archive. This plugin will use the source: tag of the archive if it exists.",
      parameters: [
        {
          name: "lang",
          type: "string",
          desc:
            "Forced language to use in searches (Japanese won't work due to EH limitations)",
        },
        {
          name: "usethumbs",
          type: "bool",
          desc: "Fetch using thumbnail first (falls back to title)",
        },
        {
          name: "search_gid",
          type: "bool",
          desc: "Search using gID from title (falls back to title)",
        },
        {
          name: "enablepanda",
          type: "bool",
          desc:
            "Use ExHentai (enable to search for fjorded content without star cookie)",
        },
        {
          name: "jpntitle",
          type: "bool",
          desc:
            "Save the original title when available instead of the English or romanised title",
        },
        {
          name: "additionaltags",
          type: "bool",
          desc:
            "Fetch additional updated_at (time posted) and uploader metadata",
        },
        {
          name: "expunged",
          type: "bool",
          desc: "Search only expunged galleries",
        },
        {
          name: "debug",
          type: "bool",
          desc: "Write verbose debug logs to data/logs/plugins.log",
        },
      ],
      oneshot_arg:
        "E-H Gallery URL (Will attach tags matching this exact gallery to your archive)",
      cooldown: 4,
      // 需要读缩略图目录以进行 file search；需要访问 upload.e-hentai.org 上传图片。
      permissions: [
        "net=e-hentai.org",
        "net=exhentai.org",
        "net=api.e-hentai.org",
        "net=upload.e-hentai.org",
        "read=./data/thumb",
      ],
      icon:
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAAEnQAABJ0Ad5mH3gAAAOASURBVDhPjVNbaFRXFF3n3puZyZ3EzJ1HkpIohthAP0InYMAKUUpfVFDylY9Bg1CJ+UllfLSEIoIEtBan7Y9t8KO0pSU0lH74oQZsMWImkSBalUADqR8mTVOTyXMymcfd7nPuNZpo2yzm3DmPfdZZZ+91MDyYJA0g+AMkStY3i8Brn392jjYKIclK7hP0rNzK7XkIIM8BdlRgkdYvvhya7bcUGT0ugKbXNZ4zcsCS+Qoycyl3y39DCL5qoJ+DpUKvM6mwzIcsFQCfjtmfL+LQX5cRa+9AOp12A57Btm1UV1ejoaHBIbTupDB/YB/yg5fcEKDo3VaUnPoWlLZBfg1zOwU6OjqQSr2o1DAMJJNJNDU1OYTBeynMNFbBPHoRwirnxOWgVW2DVhbh4wsQQR2p3VWgxXGX4uWQxJxyFyvLKHpzDzy7tsOz+w1olkMmQfKW+z/Gmc7javxvKC0t5SSywtCfRFplDYlNIRJlES65QYEbRNYQrf77bxFtKRauOYj6+vook8m4IweBAFtNXfl+CtP1FszD56VuLo6J/O/XYT98AL1+FwojQxChSuRuXsV3X55mywbR1taGlpYWlbfx8XHEYjFVFEfhQ2UyCriKAv2sapjIF/+agndZ3dmrZP1GpH/4Fb1eu0XF9vT0UHd3t+onEgkaGxuj8vJy+UieQfPzASxQNqxwyyyD2D5YmoU9PwfP3naETS+i0Siam5vBJOjq6kI8HkdNTQ2y2SzkVmZQXyydPMIEC+y/eRQfuQAU8mreznBVhIAvBFwb+YeLdA+6z0RFRQUmJiZUzFMohVKFr/UUq5jmAU/ofM5KGkWN74HY8MarnBtv8Wq1T350DLquw+PxyO1rIOC3KJicQbZ/SFpeKUGBvVfGchhaZDOEybnIs4U0HTYfOP+OABcVvb29qjCyL2FZlrysTqHJPBY+OMwbpGBJmIPx2g5FbuzYC30ze9KxJEQYmIlWclom1Xh0dBR1dXWKNBwOQxxtP0SJn/qBne+vGlmBXwtHATmujtfDP9nn3Hj9WBn4FefiB3Gi8xM32IFSKA05cvc2Jh894rysKbqCaZq48MWn+OaPrUBjTKUD37+Fqam/EYnwM30OklBK/V8spqYIRh3hB8evd4YH3ZW1YELaEKGE32sQKt6mK7/86M68CHnYhgkTifNqQ21trVKyvsm1gYEBegL+M2W04901FQAAAABJRU5ErkJggg==",
      update_url:
        "https://git.copur.xyz/copur/lanlup/raw/branch/master/Metadata/EHentai.ts",
    };
  }

  protected async runPlugin(input: PluginInput): Promise<void> {
    try {
      this.reportProgress(5, "初始化元数据搜索...");
      const params = this.getParams();
      const debug = !!params.debug;
      const targetType = this.normalizeTargetType(params.__target_type);
      const targetId = String(params.__target_id || input.archiveId || "").trim();

      if (this.isCollectionTargetType(targetType)) {
        await this.logInfo("run:collection_mode", {
          target_type: targetType,
          target_id: targetId,
        });
        const collectionResult = await this.getTagsForCollection(
          targetId,
          params.lang || "",
          params.usethumbs || false,
          params.search_gid || false,
          params.enablepanda || false,
          params.jpntitle || false,
          params.additionaltags || false,
          params.expunged || false,
          input.loginCookies || [],
          debug,
        );
        this.outputResult(collectionResult);
        return;
      }

      await this.logInfo("run:start", {
        archive_id: input.archiveId || "",
        target_type: targetType || "archive",
        has_oneshot: !!input.oneshotParam,
        title_len: (input.archiveTitle || "").length,
        has_thumbhash: !!(input.thumbnailHash || ""),
        login_cookie_count: (input.loginCookies || []).length,
        usethumbs: !!params.usethumbs,
        search_gid: !!params.search_gid,
        enablepanda: !!params.enablepanda,
        expunged: !!params.expunged,
        debug,
      });

      this.reportProgress(10, "准备搜索参数...");

      // 从 input 中获取必要信息
      const lrrInfo = {
        archive_title: input.archiveTitle || "",
        existing_tags: input.existingTags || "",
        thumbnail_hash: input.thumbnailHash || "",
        login_cookies: input.loginCookies || [],
        oneshot_param: input.oneshotParam || "",
        archive_id: input.archiveId || "",
        debug,
      };

      this.reportProgress(20, "开始搜索 E-Hentai...");

      const result = await this.getTags(
        lrrInfo,
        params.lang || "",
        params.usethumbs || false,
        params.search_gid || false,
        params.enablepanda || false,
        params.jpntitle || false,
        params.additionaltags || false,
        params.expunged || false,
      );

      this.reportProgress(100, "元数据获取完成");
      this.outputResult(result);
    } catch (error) {
      const errorMessage = error instanceof Error
        ? error.message
        : String(error);
      this.outputResult({
        success: false,
        error: `Plugin execution failed: ${errorMessage}`,
      });
    }
  }

  private normalizeTargetType(raw: unknown): string {
    return String(raw || "").trim().toLowerCase();
  }

  private isCollectionTargetType(targetType: string): boolean {
    return targetType === "tankoubon" || targetType === "tank";
  }

  private async getTagsForCollection(
    tankoubonId: string,
    lang: string,
    usethumbs: boolean,
    search_gid: boolean,
    enablepanda: boolean,
    jpntitle: boolean,
    additionaltags: boolean,
    expunged: boolean,
    loginCookies: Array<{ name: string; value: string; domain?: string; path?: string }>,
    debug: boolean,
  ): Promise<PluginResult> {
    if (!tankoubonId) {
      return {
        success: false,
        error: "Missing tankoubon target id",
      };
    }

    const members = await this.callHost<TankoubonArchivesResponse>(
      "tankoubon.listArchives",
      { tankoubonId },
    );
    const archiveIds = Array.isArray(members?.archiveIds)
      ? members.archiveIds.filter((v) => !!String(v || "").trim())
      : [];

    if (archiveIds.length === 0) {
      return {
        success: false,
        error: `No member archives found in collection ${tankoubonId}`,
      };
    }

    const patches: Array<Record<string, unknown>> = [];

    for (let i = 0; i < archiveIds.length; i += 1) {
      const archiveId = String(archiveIds[i]).trim();
      this.reportProgress(
        Math.min(95, 10 + Math.floor(((i + 1) / archiveIds.length) * 80)),
        `处理合集成员 ${i + 1}/${archiveIds.length}`,
      );

      const meta = await this.callHost<ArchiveMetadataResponse>(
        "archive.getMetadata",
        { archiveId },
      );

      const lrrInfo = {
        archive_title: String(meta?.title || ""),
        existing_tags: String(meta?.existingTags || ""),
        thumbnail_hash: String(meta?.thumbnailHash || ""),
        login_cookies: loginCookies,
        oneshot_param: "",
        archive_id: archiveId,
        debug,
      };

      const result = await this.getTags(
        lrrInfo,
        lang,
        usethumbs,
        search_gid,
        enablepanda,
        jpntitle,
        additionaltags,
        expunged,
      );

      if (!result.success || !result.data) {
        return {
          success: false,
          error: `Collection member scrape failed for archive ${archiveId}: ${result.error || "unknown error"}`,
        };
      }

      patches.push({
        archive_id: archiveId,
        title: String(result.data.title || ""),
        tags: String(result.data.tags || ""),
      });
    }

    return {
      success: true,
      data: {
        archives: patches,
      },
    };
  }

  private async getTags(
    lrrInfo: any,
    lang: string,
    usethumbs: boolean,
    search_gid: boolean,
    enablepanda: boolean,
    jpntitle: boolean,
    additionaltags: boolean,
    expunged: boolean,
  ): Promise<PluginResult> {
    let gID = "";
    let gToken = "";
    const domain = enablepanda
      ? "https://exhentai.org"
      : "https://e-hentai.org";
    const cookies = Array.isArray(lrrInfo.login_cookies)
      ? lrrInfo.login_cookies
      : [];
    const debug = !!lrrInfo.debug;

    await this.dlog(debug, "getTags:context", {
      archive_id: lrrInfo.archive_id || "",
      domain,
      title: (lrrInfo.archive_title || "").slice(0, 200),
      thumbhash: lrrInfo.thumbnail_hash
        ? `${String(lrrInfo.thumbnail_hash).slice(0, 8)}…`
        : "",
      cookie_count: cookies.length,
    });

    // 从oneshot参数或source标签提取gallery IDs
    if (
      lrrInfo.oneshot_param &&
      lrrInfo.oneshot_param.match(/.*\/g\/([0-9]*)\/([0-z]*)\/*.*/)
    ) {
      const match = lrrInfo.oneshot_param.match(
        /.*\/g\/([0-9]*)\/([0-z]*)\/*.*/,
      );
      if (match) {
        gID = match[1];
        gToken = match[2];
        await this.dlog(debug, "getTags:use_oneshot", {
          gID,
          gToken: `${gToken.slice(0, 6)}…`,
        });
      }
    } else if (
      lrrInfo.existing_tags &&
      lrrInfo.existing_tags.match(
        /.*source:\s*(?:https?:\/\/)?e(?:x|-)hentai\.org\/g\/([0-9]*)\/([0-z]*)\/*.*/gi,
      )
    ) {
      const match = lrrInfo.existing_tags.match(
        /.*source:\s*(?:https?:\/\/)?e(?:x|-)hentai\.org\/g\/([0-9]*)\/([0-z]*)\/*.*/gi,
      );
      if (match) {
        const srcMatch = match[0].match(/g\/([0-9]*)\/([0-z]*)/);
        if (srcMatch) {
          gID = srcMatch[1];
          gToken = srcMatch[2];
          await this.dlog(debug, "getTags:use_source_tag", {
            gID,
            gToken: `${gToken.slice(0, 6)}…`,
          });
        }
      }
    }

    if (!gID) {
      // 搜索matching gallery
      const searchResult = await this.lookupGallery(
        lrrInfo.archive_id,
        lrrInfo.archive_title,
        lrrInfo.existing_tags,
        lrrInfo.thumbnail_hash,
        domain,
        cookies,
        lang,
        usethumbs,
        search_gid,
        expunged,
        debug,
      );

      if (searchResult.success) {
        gID = searchResult.data.gID;
        gToken = searchResult.data.gToken;
        await this.dlog(debug, "getTags:lookup_success", {
          gID,
          gToken: `${gToken.slice(0, 6)}…`,
        });
      } else {
        await this.logWarn("getTags:lookup_failed", {
          archive_id: lrrInfo.archive_id || "",
          error: searchResult.error,
        });
        return searchResult;
      }
    }

    if (!gID) {
      return { success: false, error: "No matching EH Gallery Found!" };
    }

    // 获取tags
    const tagsResult = await this.getTagsFromEH(
      gID,
      gToken,
      jpntitle,
      additionaltags,
    );
    if (!tagsResult.success) {
      await this.logWarn("getTags:gdata_failed", {
        archive_id: lrrInfo.archive_id || "",
        gID,
        error: tagsResult.error,
      });
      return tagsResult;
    }

    const hashData: any = { tags: tagsResult.data.tags };

    // 添加source URL和title（同时添加两个域名）
    if (hashData.tags) {
      const sourceUrlEx = `https://exhentai.org/g/${gID}/${gToken}`;
      const sourceUrlE = `https://e-hentai.org/g/${gID}/${gToken}`;
      hashData.tags += `, source:${sourceUrlEx}, source:${sourceUrlE}`;
      hashData.title = tagsResult.data.title;
    }

    return { success: true, data: hashData };
  }

  private async lookupGallery(
    archiveId: string,
    title: string,
    tags: string,
    thumbhash: string,
    domain: string,
    cookies: Array<
      { name: string; value: string; domain?: string; path?: string }
    >,
    defaultlanguage: string,
    usethumbs: boolean,
    search_gid: boolean,
    expunged: boolean,
    debug: boolean,
  ): Promise<PluginResult> {
    try {
      // Reverse image search (LANraragi-style):
      // 1) Export cover from archive via host RPC and compute SHA-1 (original bytes)
      // 2) Try EH `f_shash` search first (fast)
      // 3) Fallback to uploading a JPEG (more compatible)
      if (usethumbs && archiveId) {
        try {
          const cover = await this.callHost<{
            archiveId: string;
            entryName: string;
            originalPath: string;
            originalSha1: string;
            uploadPath: string;
            uploadSha1: string;
          }>("archive.exportCoverForSearch", {
            archiveId,
            exportJpeg: true,
            maxSide: 1280,
            jpegQuality: 85,
          });

          await this.dlog(debug, "lookup:cover_exported", {
            archiveId,
            entryName: cover.entryName,
            originalSha1: cover.originalSha1
              ? `${cover.originalSha1.slice(0, 8)}…`
              : "",
            uploadPath: cover.uploadPath || "",
          });

          if (cover.originalSha1) {
            const url =
              `${domain}?f_shash=${cover.originalSha1}&fs_similar=on&fs_covers=on`;
            await this.dlog(debug, "lookup:shash_search:start", {
              sha1: `${cover.originalSha1.slice(0, 8)}…`,
            });
            const result = await this.ehentaiParse(url, cookies);
            if (result.success) {
              return result;
            }
            await this.dlog(debug, "lookup:shash_search:miss", {
              error: result.error || "unknown",
            });
          }

          if (cover.uploadPath) {
            await this.dlog(debug, "lookup:file_upload_search:start", {
              file: cover.uploadPath,
            });
            const result = await this.fileSearchByUpload(
              cover.uploadPath,
              cookies,
            );
            if (result.success) {
              return result;
            }
            await this.logWarn("lookup:file_upload_search:miss", {
              error: result.error || "unknown",
            });
          }
        } catch (e) {
          await this.logWarn("lookup:cover_export_failed", {
            archiveId,
            error: e instanceof Error ? e.message : String(e),
          });
        }
      }

      // 使用标题中的gID搜索
      if (search_gid) {
        const titleGidMatch = title.match(/\[([0-9]+)\]/g);
        if (titleGidMatch) {
          const gid = titleGidMatch[0].replace(/\[|\]/g, "");
          const url = `${domain}?f_search=gid:${gid}`;
          await this.dlog(debug, "lookup:gid_search:start", { gid });
          const result = await this.ehentaiParse(url, cookies);
          if (result.success) {
            return result;
          }
          await this.dlog(debug, "lookup:gid_search:miss", {
            error: result.error || "unknown",
          });
        }
      }

      // 常规文本搜索
      let url = `${domain}?advsearch=1&f_sfu=on&f_sft=on&f_sfl=on&f_search=${
        encodeURIComponent(`"${title}"`)
      }`;
      await this.dlog(debug, "lookup:title_search:base", {
        title: title.slice(0, 200),
      });

      // 添加artist标签
      const artistMatch = tags.match(/.*artist:\s?([^,]*),*.*/gi);
      if (artistMatch && artistMatch[0]) {
        const artist = artistMatch[0].replace(
          /.*artist:\s?([^,]*),*.*/gi,
          "$1",
        );
        if (/^[\x00-\x7F]*$/.test(artist)) {
          url += `+${encodeURIComponent(`artist:${artist}`)}`;
          await this.dlog(debug, "lookup:title_search:add_artist", { artist });
        }
      }

      // 添加语言覆盖
      if (defaultlanguage) {
        url += `+${encodeURIComponent(`language:${defaultlanguage}`)}`;
        await this.dlog(debug, "lookup:title_search:add_language", {
          language: defaultlanguage,
        });
      }

      // 搜索已删除画廊
      if (expunged) {
        url += "&f_sh=on";
        await this.dlog(debug, "lookup:title_search:expunged", {});
      }

      return await this.ehentaiParse(url, cookies);
    } catch (error) {
      const errorMessage = error instanceof Error
        ? error.message
        : String(error);
      return {
        success: false,
        error: `Gallery lookup failed: ${errorMessage}`,
      };
    }
  }

  private async ehentaiParse(
    url: string,
    cookies: Array<
      { name: string; value: string; domain?: string; path?: string }
    >,
  ): Promise<PluginResult> {
    try {
      const response = await fetch(url, {
        headers: {
          ...this.buildHeaders(url, cookies),
        },
      });

      if (!response.ok) {
        return {
          success: false,
          error: `HTTP ${response.status}: ${response.statusText}`,
        };
      }

      const html = await response.text();
      return await this.parseGalleryFromHtml(html);
    } catch (error) {
      const errorMessage = error instanceof Error
        ? error.message
        : String(error);
      return { success: false, error: `Search failed: ${errorMessage}` };
    }
  }

  private async parseGalleryFromHtml(html: string): Promise<PluginResult> {
    // 检查是否被临时禁止
    if (html.includes("Your IP address has been")) {
      return {
        success: false,
        error: "Temporarily banned from EH for excessive pageloads.",
      };
    }

    const candidates = this.extractGalleryCandidates(html);
    if (candidates.length > 0) {
      if (candidates.length === 1) {
        const only = candidates[0];
        return { success: true, data: { gID: only.gID, gToken: only.gToken } };
      }

      // Prefer EH API thumbnails for selector UI (same source as EHDB/ref crawler).
      const resolvedCandidates = await this.enrichCandidatesWithApiCovers(
        candidates,
      );
      const selectedIndex = await this.hostSelect(
        "E-Hentai 候选匹配",
        resolvedCandidates.map((item, idx) => ({
          label: item.title || `候选 ${idx + 1}`,
          description: `gid:${item.gID} | ${item.url}`,
          cover: item.cover,
        })),
        {
          message: "检测到多个匹配画廊，请选择最合适的一项",
          defaultIndex: 0,
          timeoutSeconds: 120,
        },
      );
      const picked = resolvedCandidates[selectedIndex] || resolvedCandidates[0];
      return {
        success: true,
        data: { gID: picked.gID, gToken: picked.gToken },
      };
    }

    const direct = this.extractDirectGallery(html);
    if (direct) {
      return { success: true, data: direct };
    }

    if (html.includes("No hits found")) {
      return { success: false, error: "No gallery found in search results" };
    }

    return { success: false, error: "No gallery found in search results" };
  }

  private extractGalleryCandidates(html: string): EhGalleryCandidate[] {
    const candidates: EhGalleryCandidate[] = [];
    const seen = new Set<string>();
    const re =
      /<a[^>]*href="([^"]*\/g\/(\d+)\/([^"\/?#]+)\/?[^"]*)"[^>]*>\s*<div[^>]*class="glink"[^>]*>([\s\S]*?)<\/div>/gi;
    let match: RegExpExecArray | null;
    while ((match = re.exec(html)) !== null) {
      const gID = String(match[2] || "").trim();
      const gToken = String(match[3] || "").trim();
      if (!gID || !gToken) continue;
      const key = `${gID}:${gToken}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const href = String(match[1] || "").trim();
      const url = href.startsWith("http")
        ? href
        : `https://e-hentai.org${href.startsWith("/") ? href : `/${href}`}`;
      const rawTitle = String(match[4] || "").trim();
      const title = this.htmlUnescape(
        rawTitle.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim(),
      ) || `g/${gID}`;

      const context = html.slice(
        Math.max(0, match.index - 350),
        Math.min(html.length, re.lastIndex + 600),
      );
      const cover = this.extractCoverFromContext(context, url);

      candidates.push({ gID, gToken, title, url, cover: cover || undefined });
    }
    return candidates;
  }

  private extractCoverFromContext(context: string, baseUrl: string): string {
    const img = context.match(
      /<(?:img|source)[^>]+(?:data-src|data-lazy-src|src)="([^"]+)"/i,
    );
    if (img?.[1]) {
      return this.normalizeCoverUrl(img[1], baseUrl);
    }

    const style = context.match(
      /url\(\s*['"]?([^'"\)]+)['"]?\s*\)/i,
    );
    if (style?.[1]) {
      return this.normalizeCoverUrl(style[1], baseUrl);
    }

    return "";
  }

  private normalizeCoverUrl(raw: string, baseUrl: string): string {
    const value = this.htmlUnescape(String(raw || "").trim());
    if (!value) return "";

    if (value.startsWith("data:image/")) {
      return value;
    }

    try {
      if (value.startsWith("//")) {
        return new URL(`https:${value}`).toString();
      }
      if (/^https?:\/\//i.test(value)) {
        return new URL(value).toString();
      }
      return new URL(value, baseUrl).toString();
    } catch {
      return "";
    }
  }

  private async enrichCandidatesWithApiCovers(
    candidates: EhGalleryCandidate[],
  ): Promise<EhGalleryCandidate[]> {
    if (candidates.length === 0) return candidates;

    const thumbMap = await this.fetchThumbMapFromApi(candidates);
    if (thumbMap.size === 0) {
      return candidates;
    }

    return candidates.map((item) => {
      const key = `${item.gID}:${item.gToken}`;
      const apiCover = thumbMap.get(key) || "";
      if (!apiCover || apiCover === item.cover) {
        return item;
      }
      return { ...item, cover: apiCover };
    });
  }

  private async fetchThumbMapFromApi(
    candidates: EhGalleryCandidate[],
  ): Promise<Map<string, string>> {
    const gidlist = candidates
      .map((item) => [parseInt(item.gID, 10), item.gToken] as [number, string])
      .filter((item) => Number.isFinite(item[0]) && !!item[1]);
    if (gidlist.length === 0) {
      return new Map();
    }

    try {
      const response = await fetch("https://api.e-hentai.org/api.php", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": EHentaiMetadataPlugin.USER_AGENT,
        },
        body: JSON.stringify({
          method: "gdata",
          gidlist,
          namespace: 1,
        }),
      });

      if (!response.ok) {
        return new Map();
      }

      const json = await response.json();
      const list = Array.isArray(json?.gmetadata) ? json.gmetadata : [];
      const out = new Map<string, string>();

      for (const item of list) {
        const gid = String(item?.gid || "").trim();
        const token = String(item?.token || "").trim();
        if (!gid || !token) continue;
        const cover = this.normalizeCoverUrl(
          String(item?.thumb || ""),
          "https://e-hentai.org/",
        );
        if (cover) {
          out.set(`${gid}:${token}`, cover);
        }
      }
      return out;
    } catch {
      return new Map();
    }
  }

  private extractDirectGallery(
    html: string,
  ): { gID: string; gToken: string } | null {
    const og = html.match(
      /<meta[^>]+property="og:url"[^>]+content="[^"]*\/g\/(\d+)\/([^"\/?#]+)\/?/i,
    );
    if (og?.[1] && og?.[2]) {
      return { gID: og[1], gToken: og[2] };
    }

    const canonical = html.match(
      /<link[^>]+rel="canonical"[^>]+href="[^"]*\/g\/(\d+)\/([^"\/?#]+)\/?/i,
    );
    if (canonical?.[1] && canonical?.[2]) {
      return { gID: canonical[1], gToken: canonical[2] };
    }

    return null;
  }

  private async resolveThumbnailFilePath(
    thumbhash: string,
  ): Promise<string | null> {
    const base = `./data/thumb/${thumbhash}`;
    const candidates = [
      base,
      `${base}.jpg`,
      `${base}.jpeg`,
      `${base}.png`,
      `${base}.webp`,
    ];
    for (const path of candidates) {
      try {
        const st = await Deno.stat(path);
        if (st.isFile) {
          return path;
        }
      } catch {
        // ignore
      }
    }
    return null;
  }

  private detectMimeType(path: string): string {
    const lower = path.toLowerCase();
    if (lower.endsWith(".png")) return "image/png";
    if (lower.endsWith(".webp")) return "image/webp";
    if (lower.endsWith(".jpeg") || lower.endsWith(".jpg")) return "image/jpeg";
    return "application/octet-stream";
  }

  private async fileSearchByUpload(
    thumbnailPath: string,
    cookies: Array<
      { name: string; value: string; domain?: string; path?: string }
    >,
  ): Promise<PluginResult> {
    try {
      const uploadUrl = "https://upload.e-hentai.org/image_lookup.php";
      const bytes = await Deno.readFile(thumbnailPath);
      const blob = new Blob([bytes], {
        type: this.detectMimeType(thumbnailPath),
      });
      await this.logInfo("file_search:upload", {
        file: thumbnailPath,
        size: bytes.byteLength,
        mime: this.detectMimeType(thumbnailPath),
      });

      const form = new FormData();
      form.append("sfile", blob, thumbnailPath.split("/").pop() || "cover.jpg");
      form.append("fs_similar", "on");
      form.append("fs_covers", "on");

      const response = await fetch(uploadUrl, {
        method: "POST",
        body: form,
        headers: {
          ...this.buildHeaders(uploadUrl, cookies),
        },
      });

      if (!response.ok) {
        return {
          success: false,
          error: `HTTP ${response.status}: ${response.statusText}`,
        };
      }

      const html = await response.text();
      if (html.includes("Similarity Scan was disabled")) {
        await this.logWarn("file_search:similarity_disabled", {});
      }
      return await this.parseGalleryFromHtml(html);
    } catch (error) {
      const errorMessage = error instanceof Error
        ? error.message
        : String(error);
      return { success: false, error: `File search failed: ${errorMessage}` };
    }
  }

  private async getTagsFromEH(
    gID: string,
    gToken: string,
    jpntitle: boolean,
    additionaltags: boolean,
  ): Promise<PluginResult> {
    try {
      const response = await fetch("https://api.e-hentai.org/api.php", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": EHentaiMetadataPlugin.USER_AGENT,
        },
        body: JSON.stringify({
          method: "gdata",
          gidlist: [[parseInt(gID), gToken]],
          namespace: 1,
        }),
      });

      if (!response.ok) {
        return {
          success: false,
          error: `API request failed: ${response.statusText}`,
        };
      }

      const json = await response.json();

      if (json.error) {
        return { success: false, error: json.error };
      }

      const data = json.gmetadata[0];
      if (!data) {
        return { success: false, error: "No metadata returned from API" };
      }

      const tags = [...data.tags, `category:${data.category.toLowerCase()}`];

      if (additionaltags) {
        if (data.uploader) {
          tags.push(`uploader:${data.uploader}`);
        }
        if (data.posted) {
          // Use updated_at namespace so the backend can map it to archives.updated_at.
          tags.push(`updated_at:${data.posted}`);
        }
      }

      const title = jpntitle && data.title_jpn ? data.title_jpn : data.title;

      return {
        success: true,
        data: {
          tags: tags.join(", "),
          title: this.htmlUnescape(title),
        },
      };
    } catch (error) {
      const errorMessage = error instanceof Error
        ? error.message
        : String(error);
      return { success: false, error: `API call failed: ${errorMessage}` };
    }
  }

  private htmlUnescape(text: string): string {
    return text
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
  }

  private cookieHeaderForUrl(
    url: string,
    cookies: Array<
      { name: string; value: string; domain?: string; path?: string }
    >,
  ): string {
    if (!cookies || cookies.length === 0) {
      return "";
    }
    let hostname = "";
    try {
      hostname = new URL(url).hostname;
    } catch {
      return "";
    }

    const applicable = cookies.filter((cookie) => {
      const domain = cookie.domain || "";
      if (!domain) return false;
      if (domain.startsWith(".")) {
        return hostname.endsWith(domain.substring(1));
      }
      return hostname === domain;
    });

    if (applicable.length === 0) {
      return "";
    }

    return applicable.map((c) => `${c.name}=${c.value}`).join("; ");
  }

  private buildHeaders(
    url: string,
    cookies: Array<
      { name: string; value: string; domain?: string; path?: string }
    >,
  ): Record<string, string> {
    const headers: Record<string, string> = {
      "User-Agent": EHentaiMetadataPlugin.USER_AGENT,
    };
    const cookie = this.cookieHeaderForUrl(url, cookies);
    if (cookie) {
      headers["Cookie"] = cookie;
    }
    return headers;
  }

  private async dlog(
    debug: boolean,
    message: string,
    meta?: unknown,
  ): Promise<void> {
    if (!debug) {
      return;
    }
    await this.logDebug(message, meta);
  }
}

// 运行插件
if (import.meta.main) {
  const plugin = new EHentaiMetadataPlugin();
  await plugin.handleCommand();
}

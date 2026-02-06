#!/usr/bin/env deno run

import { BasePlugin, PluginInfo, PluginInput } from "../base_plugin.ts";

type TagListItem = {
  id: number;
  namespace: string;
  name: string;
  translation_text?: string;
};

type TagsListResponse = {
  total: number;
  limit: number;
  offset: number;
  items: TagListItem[];
};

function norm(s: unknown): string {
  return String(s ?? "")
    .trim()
    .toLowerCase();
}

function nsKey(ns: string, value: string): string {
  return `${ns}\u0000${value}`;
}

function isOtherLike(ns: string): boolean {
  return ns === "other" || ns === "";
}

/**
 * Script plugin: merge duplicate tags using host-exposed operations.
 *
 * Rules:
 * 1) Same namespace: if tagA.name equals tagB.translation_text, merge A -> B
 * 2) namespace === "other" or empty: if other/empty:VALUE equals another tag's VALUE or translation_text, merge -> that tag
 *
 * Host RPC methods required:
 * - tags.list (paginated)
 * - tags.merge
 */
class TagMergeScriptPlugin extends BasePlugin {
  getPluginInfo(): PluginInfo {
    return {
      name: "Tag Merge",
      type: "script",
      namespace: "tag_merge",
      author: "lanlu",
      version: "1.0",
      description: "Merge duplicate tags based on translation/name rules.",
      parameters: [
        { type: "string", name: "lang", desc: "Translation language to use", default_value: "zh" },
        { type: "int", name: "page_size", desc: "Pagination size for tags.list", default_value: "1000" },
        { type: "bool", name: "dry_run", desc: "Only compute merges; do not change DB", default_value: "true" },
        { type: "bool", name: "delete_source", desc: "Delete source tag after merge", default_value: "true" },
        { type: "int", name: "max_merges", desc: "Max merges to apply (0 = unlimited)", default_value: "0" },
      ],
      cron_enabled: false,
      cron_expression: "0 3 * * *",
      cron_priority: 50,
      cron_timeout_seconds: 3600,
    };
  }

  protected async runPlugin(_input: PluginInput): Promise<void> {
    const params = this.getParams();
    const lang = String(params.lang ?? "zh").trim() || "zh";
    const pageSize = Math.min(2000, Math.max(1, Number(params.page_size ?? 1000)));
    const dryRun = Boolean(params.dry_run ?? true);
    const deleteSource = Boolean(params.delete_source ?? true);
    const maxMerges = Math.max(0, Number(params.max_merges ?? 0));

    await this.logInfo("tag_merge started", { lang, pageSize, dryRun, deleteSource, maxMerges });

    const tags: TagListItem[] = [];

    // For rule (1): key=(namespace, normalized translation_text) -> targetId (or 0 = ambiguous).
    const translationIndex = new Map<string, number>();

    // For rule (2): normalized name/translation -> candidate non-other tag ids.
    const canonicalCandidates = new Map<string, Set<number>>();

    // For target namespace lookup and cycle checks.
    const idToNs = new Map<number, string>();

    // First page to learn total.
    const first = (await this.callHost<TagsListResponse>("tags.list", {
      lang,
      limit: pageSize,
      offset: 0,
    })) as TagsListResponse;

    const total = Number(first.total ?? 0);
    let offset = 0;

    const ingest = (items: TagListItem[]) => {
      for (const it of items || []) {
        const id = Number(it.id);
        if (!Number.isFinite(id) || id <= 0) continue;
        const ns = String(it.namespace ?? "").trim();
        const name = String(it.name ?? "").trim();
        const t = String(it.translation_text ?? "").trim();

        tags.push({ id, namespace: ns, name, translation_text: t });
        idToNs.set(id, ns);

        if (!isOtherLike(ns)) {
          const nameKey = norm(name);
          if (nameKey) {
            let set = canonicalCandidates.get(nameKey);
            if (!set) canonicalCandidates.set(nameKey, (set = new Set()));
            set.add(id);
          }

          const trKey = norm(t);
          if (trKey) {
            let set = canonicalCandidates.get(trKey);
            if (!set) canonicalCandidates.set(trKey, (set = new Set()));
            set.add(id);

            const k = nsKey(ns, trKey);
            const prev = translationIndex.get(k);
            if (prev === undefined) translationIndex.set(k, id);
            else if (prev !== id) translationIndex.set(k, 0); // ambiguous
          }
        }
      }
    };

    ingest(first.items);
    offset += pageSize;

    while (offset < total) {
      this.reportProgress(Math.min(60, Math.floor((offset / Math.max(1, total)) * 60)), `Loading tags ${offset}/${total}`);
      const page = (await this.callHost<TagsListResponse>("tags.list", {
        lang,
        limit: pageSize,
        offset,
      })) as TagsListResponse;
      ingest(page.items);
      offset += pageSize;
    }

    this.reportProgress(65, `Building merge plan (tags=${tags.length})`);

    const sourceToTarget = new Map<number, number>();

    for (const it of tags) {
      const sourceId = Number(it.id);
      const ns = String(it.namespace ?? "").trim();
      const nameKey = norm(it.name);
      if (!nameKey) continue;

      if (isOtherLike(ns)) {
        const set = canonicalCandidates.get(nameKey);
        if (!set || set.size !== 1) continue;
        const [targetId] = [...set.values()];
        if (targetId && targetId !== sourceId) sourceToTarget.set(sourceId, targetId);
        continue;
      }

      // rule (1)
      const k = nsKey(ns, nameKey);
      const targetId = translationIndex.get(k);
      if (!targetId || targetId === 0 || targetId === sourceId) continue;
      sourceToTarget.set(sourceId, targetId);
    }

    // Resolve chains and de-dup.
    const resolve = (id: number): number => {
      let cur = id;
      const seen = new Set<number>();
      while (true) {
        const next = sourceToTarget.get(cur);
        if (!next) return cur;
        if (seen.has(next)) return cur; // cycle; stop
        seen.add(next);
        cur = next;
      }
    };

    const merges: Array<{ sourceId: number; targetId: number }> = [];
    for (const [sourceId, targetId] of sourceToTarget.entries()) {
      const finalTarget = resolve(targetId);
      if (finalTarget === sourceId) continue;
      // For rule (2), ensure target isn't "other".
      if (isOtherLike(idToNs.get(sourceId) ?? "") && isOtherLike(idToNs.get(finalTarget) ?? "")) continue;
      merges.push({ sourceId, targetId: finalTarget });
    }

    merges.sort((a, b) => a.sourceId - b.sourceId);

    await this.logInfo("merge plan built", { candidates: sourceToTarget.size, merges: merges.length });
    this.emitData("merge_plan", { merges: merges.slice(0, 200), total: merges.length });

    if (dryRun) {
      this.outputResult({ success: true, data: { dry_run: true, total_tags: tags.length, planned_merges: merges.length } });
      return;
    }

    const toApply = maxMerges > 0 ? merges.slice(0, maxMerges) : merges;
    let applied = 0;
    for (const m of toApply) {
      if (applied % 50 === 0) {
        this.reportProgress(70 + Math.floor((applied / Math.max(1, toApply.length)) * 30), `Merging ${applied}/${toApply.length}`);
      }
      await this.callHost("tags.merge", { sourceId: m.sourceId, targetId: m.targetId, deleteSource });
      applied++;
    }

    this.outputResult({ success: true, data: { dry_run: false, total_tags: tags.length, planned_merges: merges.length, applied_merges: applied } });
  }
}

await new TagMergeScriptPlugin().handleCommand();

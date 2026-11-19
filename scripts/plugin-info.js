#!/usr/bin/env node
// 从 wasm 插件里读出 lanlu_plugin_info() 返回的 JSON。
// 用法: node plugin-info.js <file.wasm>
// 依赖：wasmedge_host / wasi 的导入全部用 noop 桩，只读取 plugin_info，不执行插件逻辑。
const fs = require('fs');

const file = process.argv[2];
if (!file) {
  console.error('usage: node plugin-info.js <file.wasm>');
  process.exit(2);
}

let mod;
try {
  mod = new WebAssembly.Module(fs.readFileSync(file));
} catch (e) {
  console.error('invalid wasm: ' + e.message);
  process.exit(1);
}

const noop = () => 0;
const imports = {
  wasmedge_host: new Proxy({}, { get: () => noop }),
  wasi_snapshot_preview1: new Proxy({}, { get: () => noop }),
};
for (const imp of WebAssembly.Module.imports(mod)) {
  if (!imports[imp.module]) imports[imp.module] = new Proxy({}, { get: () => noop });
}

let inst;
try {
  inst = new WebAssembly.Instance(mod, imports);
} catch (e) {
  console.error('instantiate failed: ' + e.message);
  process.exit(1);
}

const ex = inst.exports;
if (typeof ex.lanlu_plugin_info !== 'function') {
  console.error('missing lanlu_plugin_info export');
  process.exit(1);
}

const ptr = ex.lanlu_plugin_info() >>> 0;
const len = (typeof ex.lanlu_plugin_info_len === 'function' ? ex.lanlu_plugin_info_len() : 0) >>> 0;
if (!len) {
  console.error('empty plugin info');
  process.exit(1);
}

const bytes = new Uint8Array(ex.memory.buffer, ptr, len);
const rawInfo = Buffer.from(bytes).toString('utf8');

function invalid(message) {
  console.error('invalid plugin info (' + file + '): ' + message);
  process.exit(1);
}

let info;
try {
  info = JSON.parse(rawInfo);
} catch (e) {
  invalid('invalid JSON: ' + e.message);
}

if (info === null || typeof info !== 'object' || Array.isArray(info)) {
  invalid('payload must be a JSON object');
}

const hasOwn = (key) => Object.prototype.hasOwnProperty.call(info, key);
const hasText = (value) => typeof value === 'string' && value.trim().length > 0;

if (!hasText(info.name)) {
  invalid('"name" must be a non-empty string');
}
if (!hasText(info.version)) {
  invalid('"version" must be a non-empty string');
}
for (const key of ['type', 'plugin_type']) {
  if (hasOwn(key) && typeof info[key] !== 'string') {
    invalid('"' + key + '" must be a string when present');
  }
}
if (!hasText(info.type) && !hasText(info.plugin_type)) {
  invalid('one of "type" or "plugin_type" must be a non-empty string');
}
if (hasOwn('namespace') && typeof info.namespace !== 'string') {
  invalid('"namespace" must be a string when present');
}
for (const key of ['permissions', 'pre', 'after']) {
  if (hasOwn(key) && !Array.isArray(info[key])) {
    invalid('"' + key + '" must be an array when present');
  }
}

process.stdout.write(rawInfo);

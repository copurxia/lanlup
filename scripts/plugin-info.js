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
process.stdout.write(Buffer.from(bytes).toString('utf8'));

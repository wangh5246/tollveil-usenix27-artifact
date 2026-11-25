"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");

async function main() {
    const [cli, manifestPath] = process.argv.slice(2);
    const cliPath = fs.realpathSync(cli);
    const snarkjs = require(path.dirname(path.dirname(cliPath)));
    const { buildBn128 } = createRequire(cliPath)("ffjavascript");
    const items = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const vkeyCache = new Map();
    const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));

    const curve = await buildBn128(true);
    globalThis.curve_bn128 = curve;
    const results = [];
    let passed = 0;
    try {
        for (const item of items) {
            if (!vkeyCache.has(item.vkey)) {
                vkeyCache.set(item.vkey, readJson(item.vkey));
            }
            const vk = vkeyCache.get(item.vkey);
            const pub = readJson(item.public_path);
            const proof = readJson(item.proof_path);
            const t0 = process.hrtime.bigint();
            const ok = await snarkjs.groth16.verify(vk, pub, proof);
            const dtMs = Number(process.hrtime.bigint() - t0) / 1e6;
            if (ok) passed += 1;
            results.push({ id: item.id, verified: Boolean(ok), verify_ms: Number(dtMs.toFixed(3)) });
        }
    } finally {
        delete globalThis.curve_bn128;
        await curve.terminate();
    }
    process.stdout.write(JSON.stringify({ total: items.length, passed, all_verified: passed === items.length, results }) + "\n");
    if (passed !== items.length) {
        process.exitCode = 1;
    }
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});

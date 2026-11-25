"use strict";

const fs = require("node:fs");
const readline = require("node:readline");

async function main() {
    const [calcPath, wasmPath] = process.argv.slice(2);
    const builder = require(calcPath);
    const wasm = fs.readFileSync(wasmPath);
    const wc = await builder(wasm);
    const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
    for await (const line of rl) {
        if (!line.trim()) continue;
        try {
            const req = JSON.parse(line);
            const t0 = process.hrtime.bigint();
            const buff = await wc.calculateWTNSBin(req.input, 0);
            fs.writeFileSync(req.wtns_path, buff);
            const dtMs = Number(process.hrtime.bigint() - t0) / 1e6;
            process.stdout.write(JSON.stringify({ ok: true, witness_ms: Number(dtMs.toFixed(3)) }) + "\n");
        } catch (err) {
            process.stdout.write(JSON.stringify({ ok: false, error: String(err.message || err) }) + "\n");
        }
    }
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});

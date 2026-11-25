"use strict";

const fs = require("node:fs");
const crypto = require("node:crypto");
const path = require("node:path");
const readline = require("node:readline");
const { createRequire } = require("node:module");

const SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

function scalar(x, modulus) {
    return typeof x === "string" && /^(0|[1-9][0-9]{0,76})$/.test(x) && BigInt(x) < modulus;
}

function g1(point) {
    return Array.isArray(point) && point.length === 3 && point[2] === "1" &&
        point.every((x) => scalar(x, BASE_FIELD));
}

function g2(point) {
    return Array.isArray(point) && point.length === 3 &&
        point.every((row) => Array.isArray(row) && row.length === 2 &&
            row.every((x) => scalar(x, BASE_FIELD))) && point[2][0] === "1" && point[2][1] === "0";
}

function validProof(proof) {
    return proof && proof.protocol === "groth16" &&
        (!Object.hasOwn(proof, "curve") || proof.curve === "bn128") &&
        g1(proof.pi_a) && g2(proof.pi_b) && g1(proof.pi_c);
}

function loadRegistry(registryPath) {
    const registry = new Map();
    const file = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    for (const [tag, row] of Object.entries(file)) {
        const contents = fs.readFileSync(row.path);
        const digest = crypto.createHash("sha256").update(contents).digest("hex");
        const vk = JSON.parse(contents.toString("utf8"));
        if (digest !== row.sha256 || vk.protocol !== "groth16" || vk.curve !== "bn128" ||
            vk.nPublic !== row.n_public || vk.IC.length !== row.n_public + 1 ||
            !g1(vk.vk_alpha_1) || !g2(vk.vk_beta_2) || !g2(vk.vk_gamma_2) || !g2(vk.vk_delta_2) ||
            JSON.stringify(vk.vk_gamma_2) === JSON.stringify(vk.vk_delta_2)) {
            throw new Error("Verification key failed its trusted registration");
        }
        registry.set(tag, vk);
    }
    if (!registry.size) throw new Error("Empty verification key registry");
    return registry;
}

async function main() {
    const [cli, registryPath] = process.argv.slice(2);
    const cliPath = fs.realpathSync(cli);
    const packagePath = path.dirname(path.dirname(cliPath));
    const version = JSON.parse(fs.readFileSync(path.join(packagePath, "package.json"), "utf8")).version;
    if (version !== "0.7.6") throw new Error("Expected snarkjs 0.7.6");
    const snarkjs = require(packagePath);
    const { buildBn128 } = createRequire(cliPath)("ffjavascript");
    const registry = loadRegistry(registryPath);
    const curve = await buildBn128(true);
    globalThis.curve_bn128 = curve;
    const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
    process.stdout.write(JSON.stringify({ ready: true, relations: [...registry.keys()].sort() }) + "\n");
    try {
        for await (const line of input) {
            let id = null;
            let verified = false;
            let pairingMs = null;
            try {
                if (line.length > 32 * 1024) throw new Error("Request is too large");
                const req = JSON.parse(line);
                id = req.id;
                const vk = registry.get(req.relation);
                if (Number.isSafeInteger(id) && vk && validProof(req.proof) &&
                    Array.isArray(req.public) && req.public.length === vk.nPublic &&
                    req.public.every((x) => scalar(x, SCALAR_FIELD))) {
                    const start = process.hrtime.bigint();
                    verified = (await snarkjs.groth16.verify(vk, req.public, req.proof)) === true;
                    pairingMs = Number(process.hrtime.bigint() - start) / 1e6;
                }
            } catch {
                verified = false;
            }
            process.stdout.write(JSON.stringify({ id, verified, pairing_ms: pairingMs }) + "\n");
        }
    } finally {
        delete globalThis.curve_bn128;
        await curve.terminate();
    }
}

main().catch((failure) => {
    process.stderr.write(failure.message + "\n");
    process.exitCode = 1;
});

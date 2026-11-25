// Run the generated witness calculator with assertions and read only the
// requested witness wires. A compiled .sym file supplies wire numbers.
const fs = require("node:fs");
const readline = require("node:readline");

async function main() {
    const [calculator, wasm, ...indices] = process.argv.slice(2);
    const wc = await require(calculator)(fs.readFileSync(wasm));
    const instance = wc.instance.exports;
    function readWire(index) {
        instance.getWitness(index);
        let value = 0n;
        for (let i = wc.n32 - 1; i >= 0; i--) {
            value = (value << 32n) + BigInt(instance.readSharedRWMemory(i) >>> 0);
        }
        return String(value);
    }

    const lines = readline.createInterface({ input: process.stdin });
    for await (const line of lines) {
        const input = JSON.parse(line);
        try {
            await wc._doCalculateWitness(input, true);
            process.stdout.write(JSON.stringify({ wires: indices.map(readWire) }) + "\n");
        } catch (error) {
            process.stdout.write(JSON.stringify({ rejected: String(error).includes("Assert Failed") }) + "\n");
        }
    }
}
main().catch((error) => {
    process.stderr.write(String(error) + "\n");
    process.exitCode = 1;
});

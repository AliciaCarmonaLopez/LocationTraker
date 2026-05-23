import { writeFile } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import * as paillierBigint from "paillier-bigint";

async function generateKeys() {
    try {
        const baseDir = path.dirname(fileURLToPath(import.meta.url));
        const outputDir = path.join(baseDir, "Manufacturer");
        const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(2048);

        const pubKeyJson = {
            n: publicKey.n.toString(),
            g: publicKey.g.toString()
        };

        const privKeyJson = {
            lambda: privateKey.lambda.toString(),
            mu: privateKey.mu.toString()
        };

        await writeFile(
            path.join(outputDir, "publicKeyManufacturer.json"),
            JSON.stringify(pubKeyJson, null, 2)
        );
        await writeFile(
            path.join(outputDir, "privateKeyManufacturer.json"),
            JSON.stringify(privKeyJson, null, 2)
        );
    } catch (err) {
        console.error("Error generando claves Paillier:", err);
    }
}

generateKeys();

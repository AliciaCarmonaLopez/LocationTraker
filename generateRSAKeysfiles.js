import { writeFile } from 'fs/promises';
import path from "path";
import { fileURLToPath } from "url";
import * as rsaLab from "rsalab";

async function generateKeys(){
  try{
  const baseDir = path.dirname(fileURLToPath(import.meta.url));
  const outputDir = path.join(baseDir, "Manufacturer");
        const { publicKey, privateKey } = await rsaLab.generateKeyPair(2048);
        console.log(publicKey, privateKey); // Debugging
        // Convertir BigInt a string para poder serializar
        const pubKeyJson = {
            n: publicKey.n.toString(),
            e: publicKey.e.toString()
        };

        const privKeyJson = {
            n: privateKey.n.toString(),
            d: privateKey.d.toString()
        };

        // Guardar en ficheros
        await writeFile(path.join(outputDir, "rsaPublicKeyManufacturer.json"), JSON.stringify(pubKeyJson, null, 2));
        await writeFile(path.join(outputDir, "rsaPrivateKeyManufacturer.json"), JSON.stringify(privKeyJson, null, 2));
  }catch(err){
    console.error("Error generando claves:", err);
  }
}
generateKeys();
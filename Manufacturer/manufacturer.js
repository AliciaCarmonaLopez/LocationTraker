import express from "express";
import morgan from "morgan";
import * as paillierBigint from 'paillier-bigint';
import { readFileSync } from 'fs';
import { randomBytes, createHash } from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import * as rsaLab from "rsalab";

const app = express();
const port = 5040;
const manufacturerDir = path.dirname(fileURLToPath(import.meta.url));

// // ==============================
// // 1. CARGAR DE CLAVES PAILLIER
// // ==============================
// const privKeyPath = path.join(manufacturerDir, "privateKeyManufacturer.json");
// const pubKeyPath = path.join(manufacturerDir, "publicKeyManufacturer.json");

// const privKeyJson = JSON.parse(readFileSync(privKeyPath, 'utf-8'));
// const pubKeyJson = JSON.parse(readFileSync(pubKeyPath, 'utf-8'));

// const n = BigInt(pubKeyJson.n);
// const g = BigInt(pubKeyJson.g);
// const lambda = BigInt(privKeyJson.lambda);
// const mu = BigInt(privKeyJson.mu);

// const publicKey = new paillierBigint.PublicKey(n, g);
// const privateKey = new paillierBigint.PrivateKey(lambda, mu, publicKey);

// ==============================
// 2. CARGAR DE CLAVES RSA
// ==============================
const rsaPrivKeyPath = path.join(manufacturerDir, "rsaPrivateKeyManufacturer.json");
const rsaPubKeyPath = path.join(manufacturerDir, "rsaPublicKeyManufacturer.json");

const rsaPrivJson = JSON.parse(readFileSync(rsaPrivKeyPath, 'utf-8'));
const rsaPubJson = JSON.parse(readFileSync(rsaPubKeyPath, 'utf-8'));

const rsaPublicKey = new rsaLab.RsaPublicKey(
  BigInt(rsaPubJson.n),
  BigInt(rsaPubJson.e)
);

const rsaPrivateKey = new rsaLab.RsaPrivateKey(
  BigInt(rsaPrivJson.n),
  BigInt(rsaPrivJson.d),
  rsaPublicKey
);

const issuedNonces = new Map();

app.use(morgan("dev"));
app.use(express.json());

// Middleware para detectar Mozilla
const middleware = (req, res, next) => {
  const userAgent = req.headers["user-agent"] || "";

  if (userAgent.toLowerCase().includes("firefox")) {
    console.log(userAgent);
    next();
  } else {
    res.status(403).send("Acceso permitido solo para Mozilla");
  }
};

// Ruta
app.post("/data", async (req, res) => {
  try {
    // 4. Obtener ciphertext del body
    const { ciphertext } = req.body;

    if (!ciphertext) {
      return res.status(400).send("Falta ciphertext");
    }

    const c = BigInt(ciphertext);

    // 5. Descifrar
    const plaintext = privateKey.decrypt(c);

    console.log("Mensaje descifrado:", plaintext.toString());

    res.json({
      plaintext: plaintext.toString()
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error al descifrar");
  }
});
app.get("/pubKey", async (req, res) => {
  try {
    const pubKey = readFileSync('/home/carmo/AggregationLab/publicKey.json', 'utf-8');

    res.json({ pubKey: pubKey });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error al leer la clave pública");
  }
});
// ==============================
// PUBLIC KEY RSA
// ==============================

app.get("/rsaPubKey", (req, res) => {
  res.json({
    n: rsaPublicKey.n.toString(),
    e: rsaPublicKey.e.toString()
  });
});

// ==============================
// FIRMA CERTIFICADO (DEVICE)
// ==============================

app.get("/sign", (req, res) => {
  try {
    const { certificado: certRaw, encNonce } = req.query;
    if (!certRaw || !encNonce) return res.status(400).send("Faltan parámetros");

    const certificado = JSON.parse(certRaw);
    const deviceId = certificado.deviceId;

    // 1. Validar Nonce
    const expectedNonce = issuedNonces.get(deviceId);

    if (!expectedNonce) return res.status(401).send("Nonce no encontrado");

    const devicePubKey = new rsaLab.RsaPublicKey(BigInt(certificado.publicKey.n), BigInt(certificado.publicKey.e));
    const isOk = devicePubKey.verify(BigInt(`0x${expectedNonce}`), BigInt(encNonce));

    if (!isOk) return res.status(402).send("Firma de nonce inválida");
    issuedNonces.delete(deviceId);

    // 2. Firmar Hash del Certificado
    const certHash = createHash("sha256").update(certRaw).digest("hex");
    const signature = rsaPrivateKey.sign(BigInt(`0x${certHash}`));

    res.json({ signature: signature.toString(), certHash });
  } catch (err) {
    res.status(500).send("Error interno");
  }
});

// ==============================
// FIRMA CIEGA
// ==============================

app.post("/sign", (req, res) => {
  try {
    const { blinded } = req.body;

    if (!blinded) {
      return res
        .status(400)
        .send("Falta mensaje cegado");
    }

    const blindedMessage = BigInt(blinded);

    // firmar mensaje cegado
    const blindedSignature =
      rsaPrivateKey.sign(blindedMessage);

    console.log(
      "Mensaje cegado firmado"
    );

    res.json({
      signature:
        blindedSignature.toString()
    });

  } catch (err) {
    console.error(err);
    res.status(500).send(
      "Error al firmar"
    );
  }
});

// ==============================
// INIT DEVICE
// ==============================
app.get("/init", async (req, res) => {
  const deviceId = req.query.deviceId;
  if (!deviceId) {
    return res.status(400).json({ error: "deviceId es obligatorio" });
  }
  const nonce = randomBytes(16).toString("hex");
  issuedNonces.set(deviceId, nonce);
  console.log(`Nonce generado para ${deviceId}: ${nonce}`);
  res.json({ nonce: nonce });

});

app.listen(port, () => {
  console.log(`Servidor en http://localhost:${port}`);
});
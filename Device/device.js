import express from "express";
import morgan from "morgan";
import { existsSync, readFileSync, writeFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { randomBytes, createHash } from "crypto";
import * as rsaLab from "rsalab";
import {startBeaconSender} from "./beaconSender.js";

let beaconHandle = null;
const app = express();
const port = 5041;
const deviceDir = path.dirname(fileURLToPath(import.meta.url));
const attestationPath = path.join(deviceDir, "attestationCredentials.json");
const signedCertPath = path.join(deviceDir, "signedCertificate.json");
const anonymousIdentityPath = path.join(deviceDir, "anonymousIdentity.json");
const accessTokenByCode = new Map();
const pendingBlindByCode = new Map();
const DEVICE_ID = "device-001";

app.use(morgan("dev"));
app.use(express.json());

// Serve static assets (CSS, etc.)
app.use("/public", express.static(path.join(deviceDir, "public")));

// ── Template renderer ──────────────────────────────────────────────────────
function renderTemplate(templateName, data = {}) {
    const templatePath = path.join(deviceDir, "views", templateName);
    let html = readFileSync(templatePath, "utf-8");
    for (const [key, value] of Object.entries(data)) {
        html = html.replaceAll(`{{${key}}}`, value ?? "");
    }
    return html;
}

// ── Math helpers ───────────────────────────────────────────────────────────
const mod = (value, modulus) => ((value % modulus) + modulus) % modulus;

const modPow = (base, exponent, modulus) => {
    let result = 1n;
    let b = mod(base, modulus);
    let e = exponent;
    while (e > 0n) {
        if (e & 1n) result = (result * b) % modulus;
        e >>= 1n;
        b = (b * b) % modulus;
    }
    return result;
};

const gcd = (a, b) => {
    let x = a, y = b;
    while (y !== 0n) { const t = y; y = x % y; x = t; }
    return x;
};

const extendedGcd = (a, b) => {
    if (b === 0n) return { g: a, x: 1n, y: 0n };
    const { g, x, y } = extendedGcd(b, a % b);
    return { g, x: y, y: x - (a / b) * y };
};

const modInverse = (a, m) => {
    const { g, x } = extendedGcd(a, m);
    if (g !== 1n) throw new Error("No existe inverso modular para r");
    return mod(x, m);
};

const randomBigIntBelow = (upperExclusive) => {
    if (upperExclusive <= 0n) throw new Error("Límite superior inválido");
    const bits = upperExclusive.toString(2).length;
    const bytes = Math.ceil(bits / 8);
    while (true) {
        const value = BigInt(`0x${randomBytes(bytes).toString("hex") || "00"}`);
        if (value < upperExclusive) return value;
    }
};

// ── Blind signing logic ────────────────────────────────────────────────────
const prepareBlindedCertificate = async () => {
    const punto14Keys = rsaLab.generateKeyPair(2048);
    const punto14Certificate = {
        anonId: randomBytes(8).toString("hex"),
        punto14PublicKey: {
            n: punto14Keys.publicKey.n.toString(),
            e: punto14Keys.publicKey.e.toString()
        },
        issuedAt: new Date().toISOString()
    };

    const certString = JSON.stringify(punto14Certificate);
    const hashHex = createHash("sha256").update(certString).digest("hex");
    const m = BigInt(`0x${hashHex}`);

    const keyResponse = await fetch("http://localhost:5042/rsaPubKey");
    if (!keyResponse.ok) throw new Error("No se pudo obtener la clave pública del AuthServer");
    const authPub = await keyResponse.json();
    const n = BigInt(authPub.n);
    const e = BigInt(authPub.e);

    let r = 0n;
    while (r <= 1n || gcd(r, n) !== 1n) r = randomBigIntBelow(n);

    const blindedCertificate = mod(m * modPow(r, e, n), n);
    return { punto14Keys, punto14Certificate, hashHex, m, n, e, r, blindedCertificate };
};

const sendBlindedCertificate = async (accessToken, prepared) => {
    const signRes = await fetch("http://localhost:5042/blind_sign_cert", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({ blindedCertificate: prepared.blindedCertificate.toString() })
    });
    const signPayload = await signRes.json();
    if (!signRes.ok) throw new Error(signPayload.error || "Error en firma ciega");

    const blindedSignature = BigInt(signPayload.blindedCertificateSignature || signPayload.blindedSignature);
    const rInv = modInverse(prepared.r, prepared.n);
    const anonymousSignature = mod(blindedSignature * rInv, prepared.n);

    const recovered = modPow(anonymousSignature, prepared.e, prepared.n);
    if (recovered !== prepared.m) throw new Error("La firma anónima no valida con la clave pública del AuthServer");

    const punto16AnonymousCertificateSigned = {
        certificate: prepared.punto14Certificate,
        signature: anonymousSignature.toString(),
        signer: signPayload.signer,
        verified: true,
        assembledAt: new Date().toISOString()
    };

    const identityBundle = {
        punto14Certificate: prepared.punto14Certificate,
        punto14Signature: anonymousSignature.toString(),
        punto14PrivateKey: {
            n: prepared.punto14Keys.privateKey.n.toString(),
            d: prepared.punto14Keys.privateKey.d.toString()
        },
        punto16AnonymousCertificateSigned,
        deviceStatus: "Device tiene la firma anónima para el certificado",
        signer: signPayload.signer,
        createdAt: new Date().toISOString()
    };

    writeFileSync(anonymousIdentityPath, JSON.stringify(identityBundle, null, 2));
    return {
        path: anonymousIdentityPath,
        certificateHash: prepared.hashHex,
        signaturePreview: `${identityBundle.punto14Signature.slice(0, 24)}...`,
        deviceStatus: identityBundle.deviceStatus
    };
};

const getAttestationCredentials = () => {
    if (existsSync(attestationPath)) {
        const keyFile = JSON.parse(readFileSync(attestationPath, "utf-8"));
        const pubKey = new rsaLab.RsaPublicKey(BigInt(keyFile.publicKey.n), BigInt(keyFile.publicKey.e));
        return {
            publicKey: pubKey,
            privateKey: new rsaLab.RsaPrivateKey(BigInt(keyFile.privateKey.n), BigInt(keyFile.privateKey.d), pubKey)
        };
    }
    const keys = rsaLab.generateKeyPair(2048);
    writeFileSync(attestationPath, JSON.stringify({
        publicKey: { n: keys.publicKey.n.toString(), e: keys.publicKey.e.toString() },
        privateKey: { d: keys.privateKey.d.toString(), n: keys.privateKey.n.toString() }
    }, null, 2));
    return keys;
};

// ==============================
// ENDPOINTS DE LA "PEGATINA" Y UI DEL INSTALADOR
// ==============================

// 1. La URL de la pegatina que usa el instalador
app.get("/pegatina", (req, res) => {
    const redirectUri = encodeURIComponent(`http://localhost:${port}/user_authenticated`);
    const authUrl = `http://localhost:5042/init_device?idBaliza=${DEVICE_ID}&redirect_uri=${redirectUri}`;
    res.send(renderTemplate("pegatina.html", { DEVICE_ID, authUrl }));
});

// 2. El redirect_uri al que vuelve el AuthServer
app.get("/user_authenticated", (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send("No se recibió ningún código");    
    res.send(renderTemplate("user_authenticated.html", { code }));
});

// 3. UI del paso 3 – firma ciega
app.get("/start_blind_sign", (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send("Falta code");
    if (!accessTokenByCode.has(code)) {
        return res.status(403).send("No hay access token para este código. Ejecuta primero Access Request.");
    }
    res.send(renderTemplate("ui_device_3.html", { code }));
});

// ── API endpoints (sin HTML) ───────────────────────────────────────────────

app.get("/do_access_request", async (req, res) => {
    const { code } = req.query;
    if (!existsSync(signedCertPath)) {
        return res.status(500).json({ error: "El dispositivo no tiene el certificado firmado por el fabricante todavía." });
    }
    const certData = JSON.parse(readFileSync(signedCertPath, "utf-8"));
    const certString = JSON.stringify(certData.certificado);
    try {
        const authServerUrl = `http://localhost:5042/auth_device?code=${code}&certificate=${encodeURIComponent(certString)}&signature=${certData.signature}`;
        const response = await fetch(authServerUrl);
        const result = await response.json();
        if (response.ok) {
            console.log("¡Access Token recibido exitosamente!", result);
            if (result.access_token) {
                accessTokenByCode.set(code, result.access_token);
                result.nextUiUrl = `/start_blind_sign?code=${encodeURIComponent(code)}`;
            }
        } else {
            console.error("Fallo al obtener Access Token:", result);
        }
        res.json(result);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get("/do_blind_sign", async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).json({ error: "Falta code" });
    const accessToken = accessTokenByCode.get(code);
    if (!accessToken) return res.status(403).json({ error: "No hay access token para este código. Ejecuta primero Access Request." });
    try {
        const prepared = await prepareBlindedCertificate();
        pendingBlindByCode.set(code, prepared);
        res.json({ status: "ok", blindedCertificatePreview: `${prepared.blindedCertificate.toString().slice(0, 24)}...` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/do_send_blinded_certificate", async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).json({ error: "Falta code" });
    const accessToken = accessTokenByCode.get(code);
    if (!accessToken) return res.status(403).json({ error: "No hay access token para este código. Ejecuta primero Access Request." });
    const prepared = pendingBlindByCode.get(code);
    if (!prepared) return res.status(409).json({ error: "No hay certificado cegado preparado. Pulsa primero Firma Ciega." });
    try {
        const anonymousResult = await sendBlindedCertificate(accessToken, prepared);
        pendingBlindByCode.delete(code);
        if (!beaconHandle) {
            beaconHandle = startBeaconSender(anonymousIdentityPath);
        }
        res.json({ status: "ok", anonymous_identity: anonymousResult });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==============================
// ARRANQUE DEL SERVIDOR DENTRO DEL DEVICE
// ==============================
app.listen(port, async () => {
    console.log(`Dispositivo (Pegatina) accesible en http://localhost:${port}/pegatina`);
    try {
        const { publicKey, privateKey } = getAttestationCredentials();
        const certificado = {
            deviceId: DEVICE_ID,
            publicKey: { n: publicKey.n.toString(), e: publicKey.e.toString() },
            issuedAt: new Date()
        };

        const initResponse = await fetch(`http://localhost:5040/init?deviceId=${DEVICE_ID}`);
        if (!initResponse.ok) {
            console.error("Fabricante respondió con error:", initResponse.status);
            return;
        }
        const { nonce } = await initResponse.json();
        console.log("nonce recibido: ", nonce);

        const encNonce = privateKey.sign(BigInt(`0x${nonce}`));
        const signRes = await fetch(`http://localhost:5040/sign?certificado=${encodeURIComponent(JSON.stringify(certificado))}&encNonce=${encNonce}`);
        if (signRes.ok) {
            const result = await signRes.json();
            writeFileSync(signedCertPath, JSON.stringify({ certificado, ...result }, null, 2));
            console.log("Certificado firmado y guardado en signedCertificate.json.");
        }
    } catch (err) {
        console.error("Error contactando al Manufacturer. ¿Está encendido el puerto 5040?", err.message);
    }
});
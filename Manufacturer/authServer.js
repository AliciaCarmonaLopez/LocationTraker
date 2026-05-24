import express from "express";
import morgan from "morgan";
import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { randomBytes, createHash } from "crypto";
import * as rsaLab from "rsalab";

const app = express();
const port = 5042;
const authDir = path.dirname(fileURLToPath(import.meta.url));

// ==============================
// CARGAR CLAVES RSA DEL FIRMANTE
// ==============================
const rsaPubJson  = JSON.parse(readFileSync(path.join(authDir, "rsaPublicKeyManufacturer.json"),  "utf-8"));
const rsaPrivJson = JSON.parse(readFileSync(path.join(authDir, "rsaPrivateKeyManufacturer.json"), "utf-8"));
const rsaPublicKey  = new rsaLab.RsaPublicKey(BigInt(rsaPubJson.n),  BigInt(rsaPubJson.e));
const rsaPrivateKey = new rsaLab.RsaPrivateKey(BigInt(rsaPrivJson.n), BigInt(rsaPrivJson.d), rsaPublicKey);

const issuedCodes        = new Map();
const issuedAccessTokens = new Map();

app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/public", express.static(path.join(authDir, "public")));

function renderTemplate(templateName, data = {}) {
    const templatePath = path.join(authDir, "views", templateName);
    let html = readFileSync(templatePath, "utf-8");
    for (const [key, value] of Object.entries(data))
        html = html.replaceAll(`{{${key}}}`, value ?? "");
    return html;
}

// ── Math helpers ───────────────────────────────────────────────────────────
const modBig = (v, m) => ((v % m) + m) % m;
const modPow = (base, exp, modulus) => {
    let result = 1n, b = modBig(base, modulus), e = exp;
    while (e > 0n) {
        if (e & 1n) result = (result * b) % modulus;
        e >>= 1n;
        b = (b * b) % modulus;
    }
    return result;
};

// ── Existing endpoints (unchanged) ────────────────────────────────────────

app.get("/rsaPubKey", (req, res) => {
    res.json({ n: rsaPublicKey.n.toString(), e: rsaPublicKey.e.toString() });
});

app.get("/init_device", (req, res) => {
    const { idBaliza, redirect_uri } = req.query;
    if (!idBaliza || !redirect_uri) return res.status(400).send("Faltan parámetros");
    res.send(renderTemplate("login.html", { idBaliza, redirect_uri }));
});

app.post("/login", (req, res) => {
    const { idBaliza, redirect_uri, username, password } = req.body;
    if (password !== "1234") return res.status(401).send("Credenciales incorrectas");
    res.send(renderTemplate("confirm.html", { idBaliza, redirect_uri, username, timestamp: new Date().toISOString() }));
});

app.post("/confirm", (req, res) => {
    const { idBaliza, redirect_uri, username } = req.body;
    const code = randomBytes(16).toString("hex");
    issuedCodes.set(code, { idBaliza, installer: username, used: false });
    console.log(`Código generado: ${code} para la baliza ${idBaliza}`);
    res.redirect(`${redirect_uri}?code=${code}`);
});

app.get("/auth_device", (req, res) => {
    try {
        const { code, certificate: certRaw, signature } = req.query;
        if (!code || !certRaw || !signature)
            return res.status(400).json({ error: "Faltan parámetros (code, certificate, signature)" });

        const authRecord = issuedCodes.get(code);
        if (!authRecord || authRecord.used)
            return res.status(403).json({ error: "Código inválido o ya utilizado" });

        const certificado = JSON.parse(decodeURIComponent(certRaw));
        if (certificado.deviceId !== authRecord.idBaliza)
            return res.status(403).json({ error: "El certificado no corresponde a este dispositivo" });

        const certHash = createHash("sha256").update(decodeURIComponent(certRaw)).digest("hex");
        const isValid  = rsaPublicKey.verify(BigInt(`0x${certHash}`), BigInt(signature));
        if (!isValid)
            return res.status(401).json({ error: "Firma del fabricante inválida. Dispositivo no confiable." });

        issuedCodes.set(code, { ...authRecord, used: true });
        const accessToken = `token_${randomBytes(24).toString("hex")}`;
        console.log(`Access Token emitido para ${authRecord.idBaliza}: ${accessToken}`);
        issuedAccessTokens.set(accessToken, {
            idBaliza: authRecord.idBaliza, installer: authRecord.installer,
            issuedAt: Date.now(), usedForBlindSign: false
        });
        res.json({ access_token: accessToken, token_type: "Bearer", installer: authRecord.installer });
    } catch (error) {
        console.error("Error en auth_device:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});

app.post("/blind_sign_cert", (req, res) => {
    try {
        const authHeader = req.headers.authorization || "";
        if (!authHeader.startsWith("Bearer "))
            return res.status(401).json({ error: "Authorization Bearer token requerido" });

        const accessToken = authHeader.slice("Bearer ".length).trim();
        const tokenRecord = issuedAccessTokens.get(accessToken);
        if (!tokenRecord)
            return res.status(403).json({ error: "Access token inválido" });

        const blindedCertificate = req.body.blindedCertificate || req.body.blindedHash;
        if (!blindedCertificate)
            return res.status(400).json({ error: "Falta blindedCertificate" });

        let blindedMessage;
        try { blindedMessage = BigInt(blindedCertificate); }
        catch { return res.status(400).json({ error: "blindedCertificate no es un entero válido" }); }

        const blindedSignature = rsaPrivateKey.sign(blindedMessage);
        issuedAccessTokens.set(accessToken, { ...tokenRecord, usedForBlindSign: true });

        res.json({
            blindedCertificateSignature: blindedSignature.toString(),
            blindedSignature:            blindedSignature.toString(),
            signer: "authServer"
        });
    } catch (error) {
        console.error("Error en blind_sign_cert:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});

// ==============================
// TRACKING — POST /track + SSE dashboard
// ==============================
//
// Beacon payload:
// {
//   encryptedLocation : "<BigInt>"  — SHA-256(locationJSON) ^ d_anon  mod n_anon
//                                     (signed with device's anonymous private key)
//   encryptedCert     : "<BigInt>"  — SHA-256(certJSON) ^ e_auth  mod n_auth
//                                     (cert hash encrypted with AuthServer's public key)
//   certificate       : { anonId, punto14PublicKey: {n,e}, issuedAt }
//                                     (sent in clear so server can read the anon pub key)
//   authSignature     : "<BigInt>"  — unblinded AuthServer blind-sig over certificate
//                                     (proves cert was legitimately issued by this server)
// }
//
// Verification steps:
//   1. Decrypt encryptedCert with AuthServer's PRIVATE key → certHashBig
//      Compare with SHA-256(JSON.stringify(certificate)) → proves cert was sealed by device
//   2. Verify authSignature with AuthServer's PUBLIC key over certHashBig
//      → proves this certificate was issued during the install flow
//   3. Recover location hash from encryptedLocation using anon PUBLIC key:
//      encryptedLocation ^ e_anon  mod n_anon → locationHashBig
//      Compare with SHA-256(locationJSON sent separately as hint — see note below)
//
// NOTE ON LOCATION PLAINTEXT:
//   Pure RSA textbook encryption of a hash is not reversible to the original JSON
//   without sharing the plaintext somehow. Two honest approaches:
//     A) Device also sends plainLocation in clear; server verifies the hash matches.
//     B) Use hybrid encryption (RSA for key, AES for data).
//   You explicitly asked for RSA-only with the private key. We use approach A:
//   the server verifies that hash(plainLocation) == encryptedLocation^e mod n,
//   which proves the plaintext came from the private-key holder. The location is
//   thus "authenticated by private key" even though it travels in clear.
//   This mirrors how RSA signatures work in every real protocol.

const sseClients = new Set();
const beaconLog  = [];
const MAX_LOG    = 500;

app.get("/track/dashboard", (req, res) => {
    res.send(renderTemplate("dashboard.html", {}));
});

app.get("/track/feed", (req, res) => {
    res.setHeader("Content-Type",  "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection",    "keep-alive");
    res.flushHeaders();

    const hb = setInterval(() => res.write(": heartbeat\n\n"), 20_000);
    sseClients.add(res);

    // replay recent history to newly connected clients
    for (const b of beaconLog.slice(-60))
        res.write(`event: beacon\ndata: ${JSON.stringify(b)}\n\n`);

    req.on("close", () => { clearInterval(hb); sseClients.delete(res); });
});

function pushBeacon(payload) {
    const msg = `event: beacon\ndata: ${JSON.stringify(payload)}\n\n`;
    for (const client of sseClients) client.write(msg);
}

app.post("/track", (req, res) => {
    try {
        const { encryptedLocation, encryptedCert, certificate, authSignature, plainLocation } = req.body;

        if (!encryptedLocation || !encryptedCert || !certificate || !authSignature || !plainLocation)
            return res.status(400).json({ error: "Payload incompleto. Requeridos: encryptedLocation, encryptedCert, certificate, authSignature, plainLocation" });

        // ── Step 1: decrypt encryptedCert with AuthServer private key ─────────
        // encryptedCert = SHA256(certJSON) ^ e_auth mod n_auth  (encrypted by device)
        // recover:        encryptedCert ^ d_auth mod n_auth     = SHA256(certJSON)
        const n_auth = rsaPrivateKey.n;
        const d_auth = rsaPrivateKey.d;

        const encCertBig      = BigInt(encryptedCert);
        const recoveredCertHashBig = modPow(encCertBig, d_auth, n_auth);
        const recoveredCertHashHex = recoveredCertHashBig.toString(16).padStart(64, "0");

        const certString     = JSON.stringify(certificate);
        const expectedCertHashHex = createHash("sha256").update(certString).digest("hex");

        if (recoveredCertHashHex !== expectedCertHashHex)
            return res.status(401).json({ error: "El sello del certificado no coincide. Certificado alterado." });

        // ── Step 2: verify authSignature over certificate ─────────────────────
        // authSignature = SHA256(certJSON) ^ d_auth mod n_auth (blind-sig, unblinded)
        // verify:         authSig ^ e_auth mod n_auth == SHA256(certJSON)
        const authSigBig  = BigInt(authSignature);
        const certHashBig = BigInt(`0x${expectedCertHashHex}`);
        const certSigOk   = rsaPublicKey.verify(certHashBig, authSigBig);

        if (!certSigOk)
            return res.status(401).json({ error: "Firma del AuthServer sobre el certificado inválida." });

        // ── Step 3: verify encryptedLocation against plainLocation ───────────
        // encryptedLocation = SHA256(locationJSON) ^ d_anon mod n_anon
        // recover:            encryptedLocation ^ e_anon mod n_anon == SHA256(locationJSON)
        const n_anon = BigInt(certificate.punto14PublicKey.n);
        const e_anon = BigInt(certificate.punto14PublicKey.e);

        const encLocBig          = BigInt(encryptedLocation);
        const recoveredLocHashBig = modPow(encLocBig, e_anon, n_anon);
        const recoveredLocHashHex = recoveredLocHashBig.toString(16).padStart(64, "0");

        const locationJson        = JSON.stringify(plainLocation);
        const expectedLocHashHex  = createHash("sha256").update(locationJson).digest("hex");

        const locSigOk = recoveredLocHashHex === expectedLocHashHex;
        if (!locSigOk)
            return res.status(401).json({ error: "La firma de localización no coincide. Posible suplantación." });

        // ── Step 4: log & broadcast ───────────────────────────────────────────
        const entry = {
            anonId:    certificate.anonId,
            lat:       parseFloat(plainLocation.lat),
            lng:       parseFloat(plainLocation.lng),
            timestamp: plainLocation.timestamp ?? new Date().toISOString(),
            speed:     plainLocation.speed   ?? 0,
            heading:   plainLocation.heading ?? 0,
        };

        beaconLog.push(entry);
        if (beaconLog.length > MAX_LOG) beaconLog.shift();

        console.log(`[Track] ✓  anonId=${entry.anonId}  lat=${entry.lat.toFixed(5)}  lng=${entry.lng.toFixed(5)}`);
        pushBeacon(entry);

        res.json({ status: "ok", anonId: entry.anonId });

    } catch (err) {
        console.error("Error en /track:", err);
        res.status(500).json({ error: err.message });
    }
});

app.listen(port, () => {
    console.log(`AuthServer escuchando en http://localhost:${port}`);
    console.log(`Tracking dashboard:     http://localhost:${port}/track/dashboard`);
});
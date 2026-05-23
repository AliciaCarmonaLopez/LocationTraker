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
const rsaPubKeyPath = path.join(authDir, "rsaPublicKeyManufacturer.json");
const rsaPrivKeyPath = path.join(authDir, "rsaPrivateKeyManufacturer.json");
const rsaPubJson = JSON.parse(readFileSync(rsaPubKeyPath, 'utf-8'));
const rsaPrivJson = JSON.parse(readFileSync(rsaPrivKeyPath, 'utf-8'));
const rsaPublicKey = new rsaLab.RsaPublicKey(
    BigInt(rsaPubJson.n),
    BigInt(rsaPubJson.e)
);
const rsaPrivateKey = new rsaLab.RsaPrivateKey(
    BigInt(rsaPrivJson.n),
    BigInt(rsaPrivJson.d),
    rsaPublicKey
);

// Base de datos temporal para los códigos de autorización emitidos
const issuedCodes = new Map();
const issuedAccessTokens = new Map();

app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get("/rsaPubKey", (req, res) => {
    // El device usa esta clave para cegar el hash antes de pedir firma ciega.
    res.json({
        n: rsaPublicKey.n.toString(),
        e: rsaPublicKey.e.toString()
    });
});

// ==============================
// 1. INIT DEVICE (Redirección desde la pegatina)
// ==============================
app.get("/init_device", (req, res) => {
    const { idBaliza, redirect_uri } = req.query;
    if (!idBaliza || !redirect_uri) return res.status(400).send("Faltan parámetros");

    // Simulamos la pantalla de Login del AuthServer
    res.send(`
        <h2>Login de Instalador (AuthServer)</h2>
        <p>Dispositivo a instalar: <strong>${idBaliza}</strong></p>
        <form action="/login" method="POST">
            <input type="hidden" name="idBaliza" value="${idBaliza}" />
            <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
            Usuario: <input type="text" name="username" value="instalador_1" /><br><br>
            Password: <input type="password" name="password" value="1234" /><br><br>
            <button type="submit">Iniciar Sesión</button>
        </form>
    `);
});

// ==============================
// 2. LOGIN Y PANTALLA DE CONFIRMACIÓN
// ==============================
app.post("/login", (req, res) => {
    const { idBaliza, redirect_uri, username, password } = req.body;

    if (password !== "1234") return res.status(401).send("Credenciales incorrectas");

    // Pantalla de confirmación
    res.send(`
        <h2>Confirmación de Instalación</h2>
        <p>Hola, <strong>${username}</strong>.</p>
        <p>¿Confirmas que el dispositivo <strong>${idBaliza}</strong> está instalado correctamente?</p>
        <form action="/confirm" method="POST">
            <input type="hidden" name="idBaliza" value="${idBaliza}" />
            <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
            <input type="hidden" name="username" value="${username}" />
            <button type="submit" style="background-color: green; color: white; padding: 10px;">
                Sí, confirmar instalación
            </button>
        </form>
    `);
});

// ==============================
// 3. GENERACIÓN DE CÓDIGO Y REDIRECCIÓN A LA "PEGATINA" (redirect_uri)
// ==============================
app.post("/confirm", (req, res) => {
    const { idBaliza, redirect_uri, username } = req.body;
    const code = randomBytes(16).toString("hex");

    issuedCodes.set(code, { idBaliza, installer: username, used: false });
    console.log(`Código generado: ${code} para la baliza ${idBaliza}`);

    res.redirect(`${redirect_uri}?code=${code}`);
});

// ==============================
// 4. AUTH DEVICE (Intercambio de código por Access Token)
// ==============================
app.get("/auth_device", (req, res) => {
    try {
        const { code, certificate: certRaw, signature } = req.query;

        if (!code || !certRaw || !signature) {
            return res.status(400).json({ error: "Faltan parámetros (code, certificate, signature)" });
        }

        // 1. Verificar si el código existe y es válido
        const authRecord = issuedCodes.get(code);
        if (!authRecord || authRecord.used) {
            return res.status(403).json({ error: "Código inválido o ya utilizado" });
        }

        // 2. Comprobar que el ID del certificado coincide con el asociado al código
        const certificado = JSON.parse(decodeURIComponent(certRaw));
        if (certificado.deviceId !== authRecord.idBaliza) {
            return res.status(403).json({ error: "El certificado no corresponde a este dispositivo" });
        }

        // 3. Verificar la firma del Fabricante sobre el Certificado
        const certHash = createHash("sha256").update(decodeURIComponent(certRaw)).digest("hex");
        const isValid = rsaPublicKey.verify(BigInt(`0x${certHash}`), BigInt(signature));

        if (!isValid) {
            return res.status(401).json({ error: "Firma del fabricante inválida. Dispositivo no confiable." });
        }

        // 4. Marcar código como usado y generar Access Token
        issuedCodes.set(code, { ...authRecord, used: true });

        const accessToken = `token_${randomBytes(24).toString("hex")}`;
        console.log(`Access Token emitido para ${authRecord.idBaliza}: ${accessToken}`);

        issuedAccessTokens.set(accessToken, {
            idBaliza: authRecord.idBaliza,
            installer: authRecord.installer,
            issuedAt: Date.now(),
            usedForBlindSign: false
        });

        res.json({
            access_token: accessToken,
            token_type: "Bearer",
            installer: authRecord.installer
        });

    } catch (error) {
        console.error("Error en auth_device:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});

app.post("/blind_sign_cert", (req, res) => {
    try {
        // Paso 14 (lado servidor): solo se firma si llega un access token válido.
        const authHeader = req.headers.authorization || "";
        if (!authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ error: "Authorization Bearer token requerido" });
        }

        const accessToken = authHeader.slice("Bearer ".length).trim();
        const tokenRecord = issuedAccessTokens.get(accessToken);
        if (!tokenRecord) {
            return res.status(403).json({ error: "Access token inválido" });
        }

        const blindedCertificate = req.body.blindedCertificate || req.body.blindedHash;
        if (!blindedCertificate) {
            return res.status(400).json({ error: "Falta blindedCertificate" });
        }

        let blindedMessage;
        try {
            blindedMessage = BigInt(blindedCertificate);
        } catch {
            return res.status(400).json({ error: "blindedCertificate no es un entero válido" });
        }

        // Firma RSA sobre el mensaje cegado: el servidor no conoce el hash real.
        const blindedSignature = rsaPrivateKey.sign(blindedMessage);
        issuedAccessTokens.set(accessToken, {
            ...tokenRecord,
            usedForBlindSign: true
        });

        res.json({
            blindedCertificateSignature: blindedSignature.toString(),
            blindedSignature: blindedSignature.toString(),
            signer: "authServer"
        });
    } catch (error) {
        console.error("Error en blind_sign_cert:", error);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});

app.listen(port, () => {
    console.log(`AuthServer escuchando en http://localhost:${port}`);
});
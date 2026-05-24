/**
 * beaconSender.js
 *
 * Reads anonymousIdentity.json, drives a simulated car around a Barcelona
 * route, and POSTs a signed+sealed beacon to AuthServer POST /track.
 *
 * ── Payload ──────────────────────────────────────────────────────────────
 * {
 *   encryptedLocation : "<BigInt string>"
 *       SHA-256(JSON.stringify(plainLocation)) ^ d_anon  mod n_anon
 *       Signed with the device's anonymous private key.
 *       Server verifies: encryptedLocation ^ e_anon mod n_anon == SHA-256(plainLocation)
 *
 *   encryptedCert     : "<BigInt string>"
 *       SHA-256(JSON.stringify(certificate)) ^ e_auth  mod n_auth
 *       Cert hash encrypted with the AuthServer's PUBLIC key.
 *       Server decrypts: encryptedCert ^ d_auth mod n_auth == SHA-256(certificate)
 *       This seals the certificate to the AuthServer — only it can verify the binding.
 *
 *   certificate       : { anonId, punto14PublicKey: {n, e}, issuedAt }
 *       Sent in clear so the server can extract e_anon/n_anon for step 1.
 *
 *   authSignature     : "<BigInt string>"
 *       Unblinded blind-signature from the install flow.
 *       Server verifies: authSig ^ e_auth mod n_auth == SHA-256(certificate)
 *       Proves the certificate was legitimately issued by this AuthServer.
 *
 *   plainLocation     : { lat, lng, timestamp, speed, heading }
 *       Sent in clear. The server checks that SHA-256(plainLocation) matches
 *       what it recovers from encryptedLocation — this is exactly how RSA
 *       signatures work: sign the hash, send hash+data, verify the signature.
 * }
 */

import { readFileSync, existsSync } from "fs";
import { createHash } from "crypto";

const TRACKING_URL = "http://localhost:5042/track";
const INTERVAL_MS  = 2000;

// ── BigInt math ───────────────────────────────────────────────────────────
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

// ── Barcelona routes — one per device ────────────────────────────────────
// Each route is a closed loop through a distinct part of the city.
const ROUTES = {
    // Route A: Eixample → Gràcia → Sarrià → Les Corts → Sants → Montjuïc → back
    A: [
        [41.3851,  2.1734],   // Plaça Catalunya
        [41.3964,  2.1610],   // Gràcia
        [41.4017,  2.1398],   // Sarrià
        [41.3890,  2.1225],   // Les Corts / Camp Nou
        [41.3750,  2.1498],   // Sants
        [41.3640,  2.1493],   // Montjuïc nord
        [41.3730,  2.1680],   // Paral·lel
        [41.3851,  2.1734],   // back to start
    ],
    // Route B: Barceloneta coastal loop → Poblenou → Besòs → back
    B: [
        [41.3762,  2.1897],   // Barceloneta
        [41.3720,  2.1980],   // Port Olímpic
        [41.3840,  2.2010],   // Poblenou sud
        [41.3936,  2.1962],   // Poblenou nord
        [41.4053,  2.2014],   // Besòs
        [41.4080,  2.1900],   // Sant Adrià
        [41.3950,  2.1850],   // Rambla del Poblenou
        [41.3762,  2.1897],   // back to start
    ],
    // Route C: Horta → Sant Andreu → Nou Barris → Vall d'Hebron → back
    C: [
        [41.4112,  2.1658],   // Horta
        [41.4105,  2.1870],   // Sant Andreu
        [41.4170,  2.1760],   // Nou Barris
        [41.4200,  2.1580],   // Roquetes
        [41.4130,  2.1450],   // Vall d'Hebron
        [41.4060,  2.1430],   // Vall d'Hebron sud
        [41.4112,  2.1658],   // back to start
    ],
    // Route D: Pedralbes → Diagonal → Eixample → Sagrada Família → back
    D: [
        [41.3880,  2.1140],   // Pedralbes
        [41.3920,  2.1380],   // Diagonal / Les Corts
        [41.3910,  2.1510],   // Diagonal centre
        [41.3980,  2.1620],   // Diagonal / Passeig de Gràcia
        [41.4036,  2.1744],   // Sagrada Família
        [41.3980,  2.1800],   // Clot
        [41.3900,  2.1700],   // Eixample dret
        [41.3880,  2.1140],   // back to start
    ],
    // Route E: Montjuïc full loop → port → Barceloneta → back
    E: [
        [41.3640,  2.1493],   // Montjuïc nord
        [41.3553,  2.1617],   // Montjuïc sud / Port
        [41.3600,  2.1750],   // Barceloneta sud
        [41.3762,  2.1897],   // Barceloneta nord
        [41.3730,  2.1780],   // Sant Antoni
        [41.3700,  2.1600],   // Poble Sec
        [41.3640,  2.1493],   // back to start
    ],
};

const ROUTE_KEYS = Object.keys(ROUTES);  // ['A','B','C','D','E']

function buildRoute(waypoints, steps = 50) {
    const pts = [];
    for (let i = 0; i < waypoints.length - 1; i++) {
        const [la, lo] = waypoints[i], [lb, lb2] = waypoints[i + 1];
        for (let s = 0; s < steps; s++) {
            const t = s / steps;
            pts.push([la + (lb - la) * t, lo + (lb2 - lo) * t]);
        }
    }
    return pts;
}

// Pick route deterministically from deviceId
function pickRoute(deviceId) {
    const sum  = [...deviceId].reduce((acc, c) => acc + c.charCodeAt(0), 0);
    const key  = ROUTE_KEYS[sum % ROUTE_KEYS.length];
    return { key, waypoints: ROUTES[key] };
}

function bearing([lat1, lon1], [lat2, lon2]) {
    const r = x => x * Math.PI / 180;
    const dL = r(lon2 - lon1);
    const y  = Math.sin(dL) * Math.cos(r(lat2));
    const x  = Math.cos(r(lat1)) * Math.sin(r(lat2))
              - Math.sin(r(lat1)) * Math.cos(r(lat2)) * Math.cos(dL);
    return (Math.atan2(y, x) * 180 / Math.PI + 360) % 360;
}

// ── Main ──────────────────────────────────────────────────────────────────
export function startBeaconSender(identityPath, deviceId = "device-001") {
    if (!existsSync(identityPath)) {
        console.error("[Beacon] anonymousIdentity.json not found — aborting.");
        return null;
    }

    const identity = JSON.parse(readFileSync(identityPath, "utf-8"));
    const { punto14Certificate, punto14Signature: authSignature, punto14PrivateKey } = identity;

    // Anonymous key pair
    const n_anon = BigInt(punto14PrivateKey.n);
    const d_anon = BigInt(punto14PrivateKey.d);

    // AuthServer public key — needed to encrypt the cert hash
    // Fetched once at startup
    let n_auth = null, e_auth = null;

    const { key: routeKey, waypoints } = pickRoute(deviceId);
    const route = buildRoute(waypoints, 50);

    let   idx    = 0;
    let   active = true;
    let   timer  = null;

    console.log(`[Beacon] device=${deviceId}  route=${routeKey}  points=${route.length}`);

    // Fetch AuthServer public key then start sending
    fetch("http://localhost:5042/rsaPubKey")
        .then(r => r.json())
        .then(pub => {
            n_auth = BigInt(pub.n);
            e_auth = BigInt(pub.e);
            console.log("[Beacon] AuthServer public key loaded. Starting route…");
            timer = setInterval(sendBeacon, INTERVAL_MS);
        })
        .catch(err => console.error("[Beacon] Could not fetch AuthServer public key:", err.message));

    async function sendBeacon() {
        if (!active || !n_auth) return;

        const prev    = route[(idx - 1 + route.length) % route.length];
        const current = route[idx];
        idx = (idx + 1) % route.length;

        const jitter = () => (Math.random() - 0.5) * 0.00015;

        const plainLocation = {
            lat:       current[0] + jitter(),
            lng:       current[1] + jitter(),
            timestamp: new Date().toISOString(),
            speed:     parseFloat((28 + Math.random() * 34).toFixed(2)),
            heading:   parseFloat(bearing(prev, current).toFixed(2)),
        };

        // ── 1. Sign location with anonymous private key ───────────────────
        // encryptedLocation = SHA-256(locationJSON) ^ d_anon  mod n_anon
        const locationJson    = JSON.stringify(plainLocation);
        const locationHashHex = createHash("sha256").update(locationJson).digest("hex");
        const locationHashBig = BigInt(`0x${locationHashHex}`);
        const encryptedLocation = modPow(locationHashBig, d_anon, n_anon).toString();

        // ── 2. Encrypt cert hash with AuthServer public key ───────────────
        // encryptedCert = SHA-256(certJSON) ^ e_auth  mod n_auth
        const certJson    = JSON.stringify(punto14Certificate);
        const certHashHex = createHash("sha256").update(certJson).digest("hex");
        const certHashBig = BigInt(`0x${certHashHex}`);
        const encryptedCert = modPow(certHashBig, e_auth, n_auth).toString();

        // ── 3. Assemble and send ──────────────────────────────────────────
        const payload = {
            encryptedLocation,   // SHA-256(location) ^ d_anon mod n_anon
            encryptedCert,       // SHA-256(cert)     ^ e_auth mod n_auth
            certificate: punto14Certificate,
            authSignature,       // unblinded blind-sig from install flow
            plainLocation,       // server verifies hash(this) == recovered hash
        };

        try {
            const res  = await fetch(TRACKING_URL, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body:    JSON.stringify(payload),
            });
            const json = await res.json();
            if (res.ok) {
                process.stdout.write(
                    `\r[Beacon] ✓  ${plainLocation.lat.toFixed(5)}, ${plainLocation.lng.toFixed(5)}`
                  + `  ${plainLocation.speed} km/h  ${plainLocation.heading.toFixed(0)}°   `
                );
            } else {
                console.error(`\n[Beacon] ✗  ${json.error}`);
            }
        } catch (err) {
            console.error(`\n[Beacon] network error: ${err.message}`);
        }
    }

    return {
        stop() {
            active = false;
            if (timer) clearInterval(timer);
            console.log("\n[Beacon] stopped.");
        }
    };
}
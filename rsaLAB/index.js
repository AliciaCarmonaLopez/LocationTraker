import { generateKeyPairSync } from "crypto";

const base64UrlToBuffer = (value) => {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  return Buffer.from(base64 + padding, "base64");
};

const bufferToBigInt = (buffer) => {
  const hex = buffer.toString("hex");
  return BigInt(`0x${hex || "0"}`);
};

const modPow = (base, exp, mod) => {
  if (mod <= 1n) {
    throw new Error("Invalid modulus");
  }
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % mod;
    }
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
};

export class RsaPublicKey {
  constructor(n, e) {
    this.n = n;
    this.e = e;
  }

  verify(message, signature) {
    const recovered = modPow(signature, this.e, this.n);
    return recovered === message;
  }
}

export class RsaPrivateKey {
  constructor(n, d, publicKey) {
    this.n = n;
    this.d = d;
    this.publicKey = publicKey;
  }

  sign(message) {
    return modPow(message, this.d, this.n);
  }
}

export function generateKeyPair(modulusLength = 2048) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength,
    publicExponent: 0x10001,
  });

  const pubJwk = publicKey.export({ format: "jwk" });
  const privJwk = privateKey.export({ format: "jwk" });

  const n = bufferToBigInt(base64UrlToBuffer(pubJwk.n));
  const e = bufferToBigInt(base64UrlToBuffer(pubJwk.e));
  const d = bufferToBigInt(base64UrlToBuffer(privJwk.d));

  const rsaPublicKey = new RsaPublicKey(n, e);
  const rsaPrivateKey = new RsaPrivateKey(n, d, rsaPublicKey);

  return {
    publicKey: rsaPublicKey,
    privateKey: rsaPrivateKey,
  };
}

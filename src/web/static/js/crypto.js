// secp256k1 curve parameters — single source of truth
const CURVE = {
    P: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn,
    ORDER: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n,
    Gx: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
    Gy: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
};
const G = [CURVE.Gx, CURVE.Gy];
// i mean secp256k1 krivka je public anyways, so fuck it -- key samotný se uz derivuje

// --- Math ---
function modpow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) result = result * base % mod;
        exp = exp / 2n;
        base = base * base % mod;
    }
    return result;
}

function modinv(a, m) {
    return modpow(a, m - 2n, m);
}

function pointAdd(p1, p2) {
    if (p1 === null) return p2;
    if (p2 === null) return p1;
    const [x1, y1] = p1;
    const [x2, y2] = p2;
    if (x1 === x2 && y1 !== y2) return null;
    let lam;
    if (x1 === x2) {
        lam = (3n * x1 * x1 % CURVE.P * modinv(2n * y1 % CURVE.P, CURVE.P)) % CURVE.P;
    } else {
        const dy = ((y2 - y1) % CURVE.P + CURVE.P) % CURVE.P;
        const dx = ((x2 - x1) % CURVE.P + CURVE.P) % CURVE.P;
        lam = dy * modinv(dx, CURVE.P) % CURVE.P;
    }
    const x3 = ((lam * lam - x1 - x2) % CURVE.P + CURVE.P) % CURVE.P;
    const y3 = ((lam * (x1 - x3) - y1) % CURVE.P + CURVE.P) % CURVE.P;
    return [x3, y3];
}


function scalarMul(k, point) {
    let result = null;
    let addend = point;
    while (k > 0n) {
        if (k % 2n === 1n) result = pointAdd(result, addend);
        addend = pointAdd(addend, addend);
        k = k / 2n;
    }
    return result;
}

// --- Encoding helpers ---
function bytesToHex(bytes) {
    return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
}

function bigIntToHex(n, len = 64) {
    return n.toString(16).padStart(len, "0");
}

// --- Crypto primitives ---
async function deriveSecret(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
        keyMaterial, 256
    );
    return BigInt("0x" + bytesToHex(new Uint8Array(bits))) % CURVE.ORDER;
}

async function sha256BigInt(...values) {
    const str = values.map(v => v.toString()).join("");
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return BigInt("0x" + bytesToHex(new Uint8Array(buf))) % CURVE.ORDER;
}

async function generateProof(secret, publicKey, username) {
    const rBytes = crypto.getRandomValues(new Uint8Array(32));
    const r = BigInt("0x" + bytesToHex(rBytes)) % CURVE.ORDER;
    const rPoint = scalarMul(r, G);
    const challenge = await sha256BigInt(rPoint[0], rPoint[1], publicKey[0], publicKey[1], username);
    const response = ((r - challenge * secret) % CURVE.ORDER + CURVE.ORDER) % CURVE.ORDER;
    return { rPoint, challenge, response };
}

async function deriveVaultKey(secret, saltHex) {
    const secretBytes = hexToBytes(bigIntToHex(secret, 64));
    const saltBytes = hexToBytes(saltHex);
    const keyMaterial = await crypto.subtle.importKey(
        "raw", secretBytes, "HKDF", false, ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: new TextEncoder().encode("ryus-vault-key") },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptEntry(plaintext, key) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        key,
        new TextEncoder().encode(plaintext)
    );
    return { ciphertext: bytesToHex(new Uint8Array(ciphertext)), nonce: bytesToHex(nonce) };
}

async function decryptEntry(ciphertextHex, nonceHex, key) {
    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: hexToBytes(nonceHex) },
        key,
        hexToBytes(ciphertextHex)
    );
    return new TextDecoder().decode(plaintext);
}
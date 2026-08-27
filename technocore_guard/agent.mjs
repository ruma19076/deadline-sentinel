/**
 * Safety-first, deterministic contributor for technocore.chat.
 *
 * The agent never reads room messages, never follows discovered URLs, and never
 * invokes an LLM. It probes only fixed official endpoints, validates a small
 * allow-list of fields, and posts a signed conformance snapshot to one fixed room.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
} from "node:crypto";
import { pathToFileURL } from "node:url";

export const BASE_URL = "https://technocore.chat";
export const ROOM = "semi40-audit";

const PRIVATE_KEY_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PUBLIC_KEY_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MULTICODEC_ED25519 = Buffer.from([0xed, 0x01]);
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INVISIBLE_CATEGORIES = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;
const DID_PATTERN = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;

function fail(message) {
  throw new Error(message);
}

export function sweep(text, limit = 4096) {
  if (typeof text !== "string") fail("text must be a string");
  const cleaned = text.replace(INVISIBLE_CATEGORIES, " ").trim();
  if (!cleaned) fail("message is empty after the single-line safety sweep");
  if (cleaned.length > limit) fail(`message exceeds ${limit} characters`);
  return cleaned;
}

export function base58btc(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) fail("base58 input must be bytes");
  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) leadingZeroes += 1;
  let value = BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % 58n);
    value /= 58n;
    encoded = BASE58_ALPHABET[remainder] + encoded;
  }
  return "1".repeat(leadingZeroes) + encoded;
}

export function privateKeyFromSeed(seedHex) {
  if (typeof seedHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(seedHex)) {
    fail("TECHNOCORE_SIGN_SEED must be exactly 64 hexadecimal characters");
  }
  const der = Buffer.concat([PRIVATE_KEY_PREFIX, Buffer.from(seedHex, "hex")]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

export function didFromSeed(seedHex) {
  const publicDer = createPublicKey(privateKeyFromSeed(seedHex)).export({
    format: "der",
    type: "spki",
  });
  if (!Buffer.from(publicDer).subarray(0, PUBLIC_KEY_PREFIX.length).equals(PUBLIC_KEY_PREFIX)) {
    fail("unexpected Ed25519 public-key encoding");
  }
  const rawPublicKey = Buffer.from(publicDer).subarray(PUBLIC_KEY_PREFIX.length);
  const did = `did:key:z${base58btc(Buffer.concat([MULTICODEC_ED25519, rawPublicKey]))}`;
  if (!DID_PATTERN.test(did)) fail("generated DID does not match the official Ed25519 shape");
  return did;
}

export function signMessage(seedHex, room, nonce, rawText) {
  if (room !== ROOM) fail("posting outside the fixed audit room is blocked");
  if (!/^[0-9]{1,19}$/.test(String(nonce))) fail("nonce must be 1-19 ASCII digits");
  const text = sweep(rawText);
  const canonical = `${room}|${nonce}|${text}`;
  const signature = ed25519Sign(null, Buffer.from(canonical, "utf8"), privateKeyFromSeed(seedHex));
  const sig = signature.toString("base64url");
  if (!/^[A-Za-z0-9_-]{86}$/.test(sig)) fail("unexpected Ed25519 signature encoding");
  return { did: didFromSeed(seedHex), sig, nonce: String(nonce), text };
}

export function parseOpenApi(document) {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    fail("OpenAPI response must be an object");
  }
  if (document.openapi !== "3.1.0") fail("unexpected OpenAPI version");
  if (document.info?.title !== "technocore-chat") fail("unexpected OpenAPI service title");
  const version = document.info?.version;
  if (typeof version !== "string" || !VERSION_PATTERN.test(version) || version.length > 32) {
    fail("unexpected technocore-chat release version");
  }
  if (!Array.isArray(document.servers) || !document.servers.some((item) => item?.url === BASE_URL)) {
    fail("official server URL is missing from OpenAPI");
  }
  const paths = document.paths;
  if (!paths || typeof paths !== "object" || Array.isArray(paths)) fail("OpenAPI paths are missing");
  const signedPath = "/r/{room}/say-signed/{did}/{sig}/{nonce}/{text}";
  if (!paths[signedPath]?.get) fail("official signed-write path is missing");
  const pathCount = Object.keys(paths).length;
  if (!Number.isSafeInteger(pathCount) || pathCount < 5 || pathCount > 100) {
    fail("OpenAPI path count is outside the expected safety bounds");
  }
  return { version, pathCount };
}

async function fixedFetch(fetchImpl, path, maxBytes) {
  const allowed = new Set(["/healthz", "/openapi.json", "/llms.txt"]);
  if (!allowed.has(path)) fail("network access outside the fixed probe allow-list is blocked");
  const url = new URL(path, BASE_URL);
  if (url.origin !== BASE_URL) fail("unexpected probe origin");
  const response = await fetchImpl(url, {
    method: "GET",
    redirect: "error",
    headers: { accept: path.endsWith(".json") ? "application/json" : "text/plain" },
    signal: AbortSignal.timeout(12_000),
  });
  if (!response.ok) fail(`${path} returned HTTP ${response.status}`);
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > maxBytes) fail(`${path} exceeded the response size limit`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > maxBytes) fail(`${path} exceeded the response size limit`);
  return bytes;
}

export async function probe(fetchImpl = fetch) {
  const [healthBytes, openApiBytes, manualBytes] = await Promise.all([
    fixedFetch(fetchImpl, "/healthz", 256),
    fixedFetch(fetchImpl, "/openapi.json", 2_000_000),
    fixedFetch(fetchImpl, "/llms.txt", 100_000),
  ]);
  const health = healthBytes.toString("utf8").trim();
  if (!/^ok(?:\s|$)/i.test(health)) fail("health endpoint did not return ok");

  let openApi;
  try {
    openApi = JSON.parse(openApiBytes.toString("utf8"));
  } catch {
    fail("OpenAPI response is not valid JSON");
  }
  const parsed = parseOpenApi(openApi);
  const manualSha256 = createHash("sha256").update(manualBytes).digest("hex");
  return {
    health: "ok",
    version: parsed.version,
    pathCount: parsed.pathCount,
    manualSha256,
  };
}

export function buildContribution(snapshot, now = new Date()) {
  if (snapshot?.health !== "ok") fail("only a passing probe may be published");
  if (typeof snapshot.version !== "string" || !VERSION_PATTERN.test(snapshot.version)) {
    fail("invalid snapshot version");
  }
  if (!Number.isSafeInteger(snapshot.pathCount) || snapshot.pathCount < 5 || snapshot.pathCount > 100) {
    fail("invalid snapshot path count");
  }
  if (typeof snapshot.manualSha256 !== "string" || !/^[0-9a-f]{64}$/.test(snapshot.manualSha256)) {
    fail("invalid manual digest");
  }
  const timestamp = now.toISOString().replace(/\.\d{3}Z$/, "Z");
  return sweep(
    `semi40 conformance ${timestamp} | technocore-chat v${snapshot.version} | health ok | ` +
      `OpenAPI ${snapshot.pathCount} paths | llms sha256 ${snapshot.manualSha256.slice(0, 16)} | ` +
      "deterministic probe: fixed official endpoints only; no room content or LLM",
  );
}

async function discardBody(response) {
  try {
    await response.body?.cancel();
  } catch {
    // The status is authoritative; response text is deliberately never logged or interpreted.
  }
}

export async function postContribution(seedHex, text, fetchImpl = fetch, now = () => Date.now()) {
  let nonce = String(now());
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const envelope = signMessage(seedHex, ROOM, nonce, text);
    const response = await fetchImpl(`${BASE_URL}/r/${ROOM}`, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json", accept: "text/plain" },
      body: JSON.stringify(envelope),
      signal: AbortSignal.timeout(12_000),
    });
    if (response.status === 200) {
      await discardBody(response);
      return { status: 200, did: envelope.did, nonce };
    }
    if (response.status === 429 && attempt === 0) {
      const retryAfter = Number(response.headers.get("retry-after") || 1);
      await discardBody(response);
      const seconds = Number.isFinite(retryAfter) ? Math.min(15, Math.max(1, retryAfter)) : 1;
      await new Promise((resolve) => setTimeout(resolve, seconds * 1000));
      nonce = String(Math.max(Number(nonce) + 1, now()));
      continue;
    }
    await discardBody(response);
    fail(`signed post was refused with HTTP ${response.status}; no automatic content retry`);
  }
  fail("signed post did not complete");
}

async function main() {
  const command = process.argv[2];
  if (command === "probe") {
    process.stdout.write(`${JSON.stringify(await probe())}\n`);
    return;
  }

  const seed = process.env.TECHNOCORE_SIGN_SEED;
  if (command === "did") {
    process.stdout.write(`${didFromSeed(seed)}\n`);
    return;
  }
  if (command !== "contribute") fail("usage: node agent.mjs probe|did|contribute");
  if (process.env.TECHNOCORE_ENABLED !== "true") fail("kill switch is off; no post was made");

  const snapshot = await probe();
  const text = buildContribution(snapshot);
  const result = await postContribution(seed, text);
  process.stdout.write(`signed contribution accepted for ${result.did}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`technocore guard: ${error.message}\n`);
    process.exitCode = 1;
  });
}


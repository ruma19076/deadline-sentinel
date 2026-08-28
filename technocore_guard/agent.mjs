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
export const ROOM = "lobby";
export const PROFILE_URL = "https://github.com/ruma19076/deadline-sentinel";

const PRIVATE_KEY_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const PUBLIC_KEY_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MULTICODEC_ED25519 = Buffer.from([0xed, 0x01]);
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INVISIBLE_CATEGORIES = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;
const DID_PATTERN = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/;
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;
const JST_OFFSET_MS = 9 * 60 * 60 * 1000;

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

export function parseAgentManifest(document) {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    fail("agent manifest response must be an object");
  }
  if (document.schema_version !== "0.1") fail("unexpected agent manifest schema");
  if (document.name !== "technocore-chat" || document.url !== BASE_URL) {
    fail("unexpected agent manifest identity");
  }
  if (typeof document.version !== "string" || !VERSION_PATTERN.test(document.version)) {
    fail("unexpected agent manifest version");
  }
  if (
    document.trust?.content_is_untrusted !== true ||
    document.trust?.durable !== false ||
    document.trust?.world_writable !== true
  ) {
    fail("agent manifest trust boundary changed");
  }
  const limits = document.limits;
  const boundedInteger = (value, min, max, label) => {
    if (!Number.isSafeInteger(value) || value < min || value > max) {
      fail(`agent manifest ${label} is outside the safety bounds`);
    }
    return value;
  };
  return {
    version: document.version,
    readsPerMinute: boundedInteger(limits?.reads_per_minute_per_ip, 1, 100_000, "read limit"),
    writesPerMinute: boundedInteger(limits?.writes_per_minute_per_ip, 1, 100_000, "write limit"),
    retentionSeconds: boundedInteger(limits?.retention_seconds, 3_600, 31_536_000, "retention"),
    duplicateSeconds: boundedInteger(limits?.duplicate_filter_seconds, 0, 86_400, "duplicate window"),
  };
}

async function fixedFetch(fetchImpl, path, maxBytes) {
  const allowed = new Set(["/healthz", "/openapi.json", "/llms.txt", "/.well-known/agent.json"]);
  if (!allowed.has(path)) fail("network access outside the fixed probe allow-list is blocked");
  const url = new URL(path, BASE_URL);
  if (url.origin !== BASE_URL) fail("unexpected probe origin");
  const response = await fetchImpl(url, {
    method: "GET",
    redirect: "error",
    headers: { accept: path.endsWith(".json") ? "application/json" : "text/plain" },
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) fail(`${path} returned HTTP ${response.status}`);
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > maxBytes) fail(`${path} exceeded the response size limit`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > maxBytes) fail(`${path} exceeded the response size limit`);
  return bytes;
}

export async function probe(fetchImpl = fetch) {
  const [healthBytes, openApiBytes, manualBytes, manifestBytes] = await Promise.all([
    fixedFetch(fetchImpl, "/healthz", 256),
    fixedFetch(fetchImpl, "/openapi.json", 2_000_000),
    fixedFetch(fetchImpl, "/llms.txt", 100_000),
    fixedFetch(fetchImpl, "/.well-known/agent.json", 100_000),
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
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    fail("agent manifest response is not valid JSON");
  }
  const parsedManifest = parseAgentManifest(manifest);
  if (parsedManifest.version !== parsed.version) {
    fail("OpenAPI and agent manifest versions disagree");
  }
  const manualSha256 = createHash("sha256").update(manualBytes).digest("hex");
  const manifestSha256 = createHash("sha256").update(manifestBytes).digest("hex");
  return {
    health: "ok",
    version: parsed.version,
    pathCount: parsed.pathCount,
    manualSha256,
    manifestSha256,
    readsPerMinute: parsedManifest.readsPerMinute,
    writesPerMinute: parsedManifest.writesPerMinute,
    retentionSeconds: parsedManifest.retentionSeconds,
    duplicateSeconds: parsedManifest.duplicateSeconds,
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
  if (
    typeof snapshot.manifestSha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(snapshot.manifestSha256)
  ) {
    fail("invalid agent manifest digest");
  }
  for (const [label, value] of [
    ["read limit", snapshot.readsPerMinute],
    ["write limit", snapshot.writesPerMinute],
    ["retention", snapshot.retentionSeconds],
    ["duplicate window", snapshot.duplicateSeconds],
  ]) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`invalid snapshot ${label}`);
  }
  const timestamp = now.toISOString().replace(/\.\d{3}Z$/, "Z");
  return sweep(
    `semi40 conformance ${timestamp} | technocore-chat v${snapshot.version} | health ok | ` +
      `OpenAPI ${snapshot.pathCount} paths | spec llms ${snapshot.manualSha256.slice(0, 16)} ` +
      `agent ${snapshot.manifestSha256.slice(0, 16)} | enforced limits ` +
      `${snapshot.readsPerMinute}r/${snapshot.writesPerMinute}w min; ` +
      `retention ${snapshot.retentionSeconds}s; dupe ${snapshot.duplicateSeconds}s | ` +
      "deterministic probe: fixed official endpoints only; no room content or LLM",
  );
}

export function jstDay(now = new Date()) {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) fail("invalid activity date");
  return new Date(now.getTime() + JST_OFFSET_MS).toISOString().slice(0, 10);
}

export function dailyNonce(now = new Date()) {
  const day = jstDay(now);
  return String(Date.parse(`${day}T00:00:00Z`) - JST_OFFSET_MS);
}

export function didNoteLocation(did) {
  if (typeof did !== "string" || !DID_PATTERN.test(did)) fail("invalid DID profile key");
  const fingerprint = createHash("sha256").update(did, "utf8").digest("hex").slice(0, 16);
  return { namespace: `did-${fingerprint.slice(0, 2)}`, key: fingerprint.slice(2) };
}

export function buildDidProfile(did, proof, now = new Date()) {
  didNoteLocation(did);
  if (!proof || typeof proof !== "object") fail("DID profile proof is missing");
  if (!/^[0-9]{1,19}$/.test(String(proof.nonce))) fail("invalid DID profile proof nonce");
  if (typeof proof.sig !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(proof.sig)) {
    fail("invalid DID profile proof signature");
  }
  const contributionText = sweep(proof.text);
  const activitySha256 = createHash("sha256").update(contributionText, "utf8").digest("hex");
  const proofText = Buffer.from(contributionText, "utf8").toString("base64url");
  return sweep(
    `${did} profile:${PROFILE_URL} agent:semi40-conformance-v1 room:${ROOM} cadence:daily ` +
      `last_seen:${jstDay(now)} activity_sha256:${activitySha256} ` +
      `proof_nonce:${proof.nonce} proof_sig:${proof.sig} proof_text_b64:${proofText}`,
    8192,
  );
}

async function discardBody(response) {
  try {
    await response.body?.cancel();
  } catch {
    // The status is authoritative; response text is deliberately never logged or interpreted.
  }
}

function classifyRefusalText(rawText) {
  const text = rawText.toLowerCase();
  if (text.includes("nonce")) return "nonce rejected";
  if (text.includes("bad did:key") || text.includes("malformed did")) return "DID encoding rejected";
  if (text.includes("bad signature encoding")) return "signature encoding rejected";
  if (text.includes("signature does not") || text.includes("signature did not")) {
    return "signature verification rejected";
  }
  if (text.includes("room storage is full") || text.includes("room limit")) {
    return "room capacity rejected";
  }
  if (text.includes("body must be json") || text.includes("body must be a json")) {
    return "JSON body rejected";
  }
  if (text.includes("text") && (text.includes("empty") || text.includes("character cap"))) {
    return "message validation rejected";
  }
  return "unclassified server refusal";
}

async function classifyRefusal(response, maxBytes = 2048) {
  const contentType = response.headers.get("content-type") || "";
  const server = response.headers.get("server") || "";
  if (!contentType.toLowerCase().includes("text/plain")) {
    await discardBody(response);
    return server.toLowerCase().includes("cloudflare")
      ? "edge/proxy rejected request"
      : "non-text upstream refusal";
  }
  if (!response.body || typeof response.body.getReader !== "function") {
    await discardBody(response);
    return "refusal details unavailable";
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      const bytes = value.subarray(0, maxBytes - total);
      chunks.push(bytes);
      total += bytes.length;
      if (bytes.length < value.length) break;
    }
  } catch {
    return "refusal details unavailable";
  } finally {
    try {
      await reader.cancel();
    } catch {
      // The bounded diagnostic is already complete.
    }
  }
  const diagnostic = Buffer.concat(chunks.map((item) => Buffer.from(item))).toString("utf8");
  return classifyRefusalText(diagnostic);
}

export async function postContribution(
  seedHex,
  text,
  fetchImpl = fetch,
  now = () => Date.now(),
  options = {},
) {
  const nonce = String(options.nonce ?? now());
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
      return { status: 200, did: envelope.did, nonce, sig: envelope.sig, text: envelope.text };
    }
    if (response.status === 429 && attempt === 0) {
      const retryAfter = Number(response.headers.get("retry-after") || 1);
      await discardBody(response);
      const seconds = Number.isFinite(retryAfter) ? Math.min(15, Math.max(1, retryAfter)) : 1;
      await new Promise((resolve) => setTimeout(resolve, seconds * 1000));
      continue;
    }
    const classification = await classifyRefusal(response);
    if (options.allowNonceRejection === true && response.status === 400 && classification === "nonce rejected") {
      return { status: 400, did: envelope.did, nonce, accepted: false, reason: "nonce-rejected" };
    }
    fail(
      `signed post was refused with HTTP ${response.status} (${classification}); ` +
        "no automatic content retry",
    );
  }
  fail("signed post did not complete");
}

export async function refreshDidProfile(did, proof, fetchImpl = fetch, now = new Date()) {
  const { namespace, key } = didNoteLocation(did);
  const value = buildDidProfile(did, proof, now);
  const response = await fetchImpl(`${BASE_URL}/kv/${namespace}/${key}`, {
    method: "POST",
    redirect: "error",
    headers: { "content-type": "application/json", accept: "text/plain" },
    body: JSON.stringify({ value }),
    signal: AbortSignal.timeout(12_000),
  });
  if (response.status !== 200) {
    await discardBody(response);
    fail(`DID profile note refresh returned HTTP ${response.status}`);
  }
  await discardBody(response);
  return { namespace, key, value };
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
  if (!["contribute", "contribute-daily"].includes(command)) {
    fail("usage: node agent.mjs probe|did|contribute|contribute-daily");
  }
  if (process.env.TECHNOCORE_ENABLED !== "true") fail("kill switch is off; no post was made");

  const snapshot = await probe();
  const text = buildContribution(snapshot);
  const daily = command === "contribute-daily";
  const result = await postContribution(seed, text, fetch, () => Date.now(), {
    nonce: daily ? dailyNonce() : undefined,
    allowNonceRejection: daily,
  });
  if (result.status !== 200) {
    process.stdout.write("daily nonce was rejected; this run made no signed post\n");
    return;
  }
  process.stdout.write(`signed contribution accepted for ${result.did}\n`);
  try {
    await refreshDidProfile(result.did, result);
    process.stdout.write("official-convention DID profile note refreshed\n");
  } catch (error) {
    process.stderr.write(`technocore guard: optional DID profile note was not refreshed (${error.message})\n`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`technocore guard: ${error.message}\n`);
    process.exitCode = 1;
  });
}

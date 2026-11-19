/** DRAFT_HOLD F4 cycle-control CAS route, isolated from Permit journal events. */
import type { CasDependencies, CasStoredDocument } from "./core.ts";

export const F4_CONTROL_KEY = "repositories/1458303357/b09-f4-cycle-control-v1.json";
export const F4_CONTROL_TEST_KEY = "repositories/1458303357/b09-f4-cycle-control-test-v1.json";
const REPOSITORY_ID = 1458303357;
const encoder = new TextEncoder();
const shaPattern = /^[0-9a-f]{64}$/;
const gitPattern = /^[0-9a-f]{40}$/;
const fields = {
  CONTROL_CREATED: ["event", "revocation_status"],
  REVOCATION_STATUS: ["event", "revocation_status"],
  CYCLE_CLAIMED: ["event", "cycle_number", "run_id", "go_sha256", "revocation_sequence", "revocation_digest", "claimed_at", "source_commit_sha"],
  CYCLE1_AUDITOR_PASS: ["event", "artifact_envelope_sha256", "artifact_id", "artifact_archive_digest", "workflow_run_id", "run_attempt", "worker_run_id", "auditor_run_id", "source_commit_sha", "auditor_envelope"],
} as const;
type EventKind = keyof typeof fields;
type ControlRole = "owner" | "worker" | "auditor" | "reader";
type ControlMode = "formal" | "test";

const AUDIT_WORKFLOW_PATH = ".github/workflows/public-runner-draft.yml";
const auditPayloadFields = [
  "schema", "kind", "repository_id", "approval_id", "go_sha256", "cycle_number",
  "worker_run_id", "auditor_run_id", "workflow_run_id", "run_attempt", "workflow_path",
  "source_commit_sha", "base_sha", "pr_number", "pr_state", "pr_is_draft", "pr_merged",
  "pr_head_sha", "pr_base_sha", "readonly_ci_run_id", "readonly_ci_conclusion",
  "permit_id", "candidate_digest", "witness_digest", "journal_revision",
  "journal_head_sha256", "result", "issued_at", "expires_at",
];

const credentials = [
  ["B09_F4_CONTROL_OWNER_BEARER", "formal", "owner"],
  ["B09_F4_CONTROL_WORKER_BEARER", "formal", "worker"],
  ["B09_F4_CONTROL_AUDITOR_BEARER", "formal", "auditor"],
  ["B09_F4_CONTROL_READ_BEARER", "formal", "reader"],
  ["B09_F4_TEST_CONTROL_OWNER_BEARER", "test", "owner"],
  ["B09_F4_TEST_CONTROL_WORKER_BEARER", "test", "worker"],
  ["B09_F4_TEST_CONTROL_AUDITOR_BEARER", "test", "auditor"],
  ["B09_F4_TEST_CONTROL_READ_BEARER", "test", "reader"],
] as const;

export async function handleF4ControlRequest(
  request: Request,
  dependencies: CasDependencies,
): Promise<Response> {
  const principal = identify(request.headers.get("authorization"), dependencies.env);
  if (!principal || !dependencies.store) return response(principal ? 503 : 401);
  const path = new URL(request.url).pathname;
  const formalPath = path === "/functions/v1/sake-cas-v1/" + F4_CONTROL_KEY || path === "/" + F4_CONTROL_KEY;
  const testPath = path === "/functions/v1/sake-cas-v1/" + F4_CONTROL_TEST_KEY || path === "/" + F4_CONTROL_TEST_KEY;
  if (!formalPath && !testPath) return response(404);
  const mode: ControlMode = formalPath ? "formal" : "test";
  if (principal.mode !== mode) return response(403);
  const key = formalPath ? F4_CONTROL_KEY : F4_CONTROL_TEST_KEY;
  if (request.method === "GET") {
    try {
      const stored = await dependencies.store.read(key);
      if (!stored) return response(404);
      await validateDocument(stored, mode, dependencies.env);
      return new Response(stored.body, {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", etag: etag(stored.revision) },
      });
    } catch { return response(503); }
  }
  if (request.method !== "PUT") return new Response(null, { status: 405, headers: { allow: "GET, PUT" } });
  if (principal.role === "reader") return response(403);
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get("content-type") ?? "")) return response(415);
  const ifMatch = request.headers.get("if-match");
  const ifNoneMatch = request.headers.get("if-none-match");
  if ((ifMatch === null) === (ifNoneMatch === null)) return response(428);
  if (ifNoneMatch !== null && ifNoneMatch !== "*") return response(412);
  let next: CasStoredDocument;
  try {
    const bytes = await readBounded(request, 1024 * 1024);
    const body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parsed = JSON.parse(body) as { sequence: number };
    next = { revision: parsed.sequence, body };
    await validateDocument(next, mode, dependencies.env);
  } catch { return response(409); }

  try {
    const current = await dependencies.store.read(key);
    if (ifNoneMatch === "*") {
      if (current || next.revision !== 1 || principal.role !== "owner") return response(412);
      const revision = await dependencies.store.insertIfAbsent(key, next.body);
      return revision === undefined ? response(412) : new Response(null, { status: 204, headers: { etag: etag(revision) } });
    }
    if (!current || ifMatch !== etag(current.revision)) return response(412);
    await validateDocument(current, mode, dependencies.env);
    const previous = JSON.parse(current.body) as { events: Array<{ payload: Record<string, unknown> }> };
    const after = JSON.parse(next.body) as Record<string, unknown> & { events: Array<{ payload: Record<string, unknown> }> };
    const appendedKind = after.events[after.events.length - 1]?.payload?.event;
    if (!roleMayAppend(principal.role, appendedKind)) return response(403);
    if (!validTransition(previous.events, after.events, principal.role, after)) return response(409);
    const revision = await dependencies.store.updateIfRevision(key, current.revision, next.body);
    return revision === undefined ? response(412) : new Response(null, { status: 204, headers: { etag: etag(revision) } });
  } catch {
    // An ambiguous or failed CAS write is never retried.
    return response(503);
  }
}

function identify(auth: string | null, env: CasDependencies["env"]): { mode: ControlMode; role: ControlRole } | null {
  if (!auth?.startsWith("Bearer ")) return null;
  const values = credentials.map(([name, mode, role]) => ({ name, mode, role, token: env.get(name) ?? "" }));
  if (values.some(({ token }) => encoder.encode(token).length < 32)) return null;
  for (let i = 0; i < values.length; i++) for (let j = i + 1; j < values.length; j++) {
    if (constantEqual(values[i].token, values[j].token)) return null;
  }
  const candidate = auth.slice(7);
  const matches = values.filter(({ token }) => constantEqual(candidate, token));
  return matches.length === 1 ? { mode: matches[0].mode, role: matches[0].role } : null;
}

async function validateDocument(stored: CasStoredDocument, mode: ControlMode, env: CasDependencies["env"]): Promise<void> {
  const value = JSON.parse(stored.body) as Record<string, unknown>;
  const expected = ["schema", "repository_id", "approval_id", "go_sha256", "base_sha", "go_revocation_sequence", "revocation_sequence", "sequence", "head_sha256", "events"];
  if (!exact(value, expected) || value.schema !== 1 || value.repository_id !== REPOSITORY_ID
      || typeof value.approval_id !== "string" || !value.approval_id
      || typeof value.go_sha256 !== "string" || !shaPattern.test(value.go_sha256)
      || typeof value.base_sha !== "string" || !gitPattern.test(value.base_sha)
      || !Number.isSafeInteger(value.sequence) || value.sequence !== stored.revision
      || !Number.isSafeInteger(value.go_revocation_sequence) || !Number.isSafeInteger(value.revocation_sequence)
      || !Array.isArray(value.events) || value.events.length !== value.sequence) throw new Error("control_scope_invalid");
  let previous = "0".repeat(64);
  for (let i = 0; i < value.events.length; i++) {
    const event = value.events[i] as Record<string, unknown>;
    if (!exact(event, ["sequence", "previous_sha256", "payload", "event_sha256"])
        || event.sequence !== i + 1 || event.previous_sha256 !== previous
        || !event.payload || typeof event.payload !== "object" || Array.isArray(event.payload)) throw new Error("control_event_invalid");
    const payload = event.payload as Record<string, unknown>;
    const kind = payload.event as EventKind;
    if (!(kind in fields) || !exact(payload, [...fields[kind]])) throw new Error("control_event_shape_invalid");
    const digest = await sha256(canonical({ sequence: event.sequence, previous_sha256: previous, payload }));
    if (event.event_sha256 !== digest) throw new Error("control_chain_invalid");
    previous = digest;
  }
  if (value.head_sha256 !== previous || value.revocation_sequence !== revocationSequence(value.events as Array<{ payload: Record<string, unknown> }>)) throw new Error("control_head_invalid");
  if (mode === "test" && value.approval_id.toString().startsWith("TEST:") === false) throw new Error("test_control_scope_invalid");
  if (mode === "formal" && value.approval_id.toString().startsWith("TEST:")) throw new Error("formal_control_scope_invalid");
  await verifyStoredSignatures(value, env);
  if (!validHistory(value.events as Array<{ payload: Record<string, unknown> }>, value)) throw new Error("control_transition_invalid");
}

function validTransition(previous: Array<{ payload: Record<string, unknown> }>, next: Array<{ payload: Record<string, unknown> }>, role: ControlRole, document: Record<string, unknown>): boolean {
  if (next.length !== previous.length + 1 || previous.some((event, i) => canonical(event) !== canonical(next[i]))) return false;
  const event = next[next.length - 1]?.payload;
  if (!event) return false;
  const roleMatches = previous.length === 0
    ? role === "owner" && event.event === "CONTROL_CREATED"
    : event.event === "REVOCATION_STATUS" ? role === "owner"
    : event.event === "CYCLE_CLAIMED" ? role === "worker"
    : event.event === "CYCLE1_AUDITOR_PASS" ? role === "auditor" : false;
  return roleMatches && validHistory(next, document);
}

function roleMayAppend(role: ControlRole, kind: unknown): boolean {
  return (role === "owner" && (kind === "CONTROL_CREATED" || kind === "REVOCATION_STATUS"))
    || (role === "worker" && kind === "CYCLE_CLAIMED")
    || (role === "auditor" && kind === "CYCLE1_AUDITOR_PASS");
}

function validHistory(events: Array<{ payload: Record<string, unknown> }>, document: Record<string, unknown> | null): boolean {
  if (!events.length || events[0].payload.event !== "CONTROL_CREATED") return false;
  const first = events[0].payload.revocation_status as { payload?: Record<string, unknown> };
  let status = first?.payload;
  if (!signedRevocation(events[0].payload.revocation_status)
      || !status || status.status !== "ACTIVE" || !Number.isSafeInteger(status.sequence)) return false;
  if (document && (status.sequence !== document.go_revocation_sequence
      || status.approval_id !== document.approval_id || status.go_sha256 !== document.go_sha256)) return false;
  const claims: Array<Record<string, unknown>> = [];
  let audited = false;
  for (const entry of events.slice(1)) {
    const payload = entry.payload;
    if (payload.event === "REVOCATION_STATUS") {
      const envelope = payload.revocation_status as { payload?: Record<string, unknown> };
      const next = envelope?.payload;
      if (!signedRevocation(payload.revocation_status) || !next || status.status !== "ACTIVE" || !["REVOKED", "STOPPED"].includes(String(next.status))
          || next.sequence !== Number(status.sequence) + 1 || next.approval_id !== status.approval_id
          || next.go_sha256 !== status.go_sha256) return false;
      status = next;
      continue;
    }
    if (payload.event === "CYCLE_CLAIMED") {
      const cycle = payload.cycle_number;
      if (status.status !== "ACTIVE" || cycle !== claims.length + 1 || (cycle !== 1 && cycle !== 2)
          || (document && payload.go_sha256 !== document.go_sha256)
          || (document && payload.revocation_sequence !== status.sequence)
          || typeof payload.revocation_digest !== "string" || !shaPattern.test(payload.revocation_digest)
          || typeof payload.run_id !== "string" || !payload.run_id || claims.some((claim) => claim.run_id === payload.run_id)
          || typeof payload.source_commit_sha !== "string" || !gitPattern.test(payload.source_commit_sha)
          || (cycle === 2 && (!audited || claims.length !== 1))) return false;
      claims.push(payload);
      continue;
    }
    if (payload.event === "CYCLE1_AUDITOR_PASS") {
      if (claims.length !== 1 || audited || claims[0].cycle_number !== 1
          || payload.worker_run_id !== claims[0].run_id
          || payload.source_commit_sha !== claims[0].source_commit_sha
          || typeof payload.artifact_id !== "number" || !Number.isSafeInteger(payload.artifact_id) || payload.artifact_id <= 0
          || typeof payload.artifact_envelope_sha256 !== "string" || !shaPattern.test(payload.artifact_envelope_sha256)
          || typeof payload.artifact_archive_digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(payload.artifact_archive_digest)
          || typeof payload.workflow_run_id !== "string" || !/^\d+$/.test(payload.workflow_run_id)
          || typeof payload.auditor_run_id !== "string" || !payload.auditor_run_id
          || !Number.isSafeInteger(payload.run_attempt) || Number(payload.run_attempt) < 1
          || !payload.auditor_envelope || typeof payload.auditor_envelope !== "object" || Array.isArray(payload.auditor_envelope)) return false;
      audited = true;
      continue;
    }
    return false;
  }
  return !document || status?.sequence === document.revocation_sequence;
}

function revocationSequence(events: Array<{ payload: Record<string, unknown> }>): unknown {
  let current: unknown;
  for (const event of events) if (event.payload.event === "CONTROL_CREATED" || event.payload.event === "REVOCATION_STATUS") {
    const envelope = event.payload.revocation_status as { payload?: { sequence?: unknown } };
    current = envelope?.payload?.sequence;
  }
  return current;
}

function signedRevocation(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const envelope = value as Record<string, unknown>;
  if (!exact(envelope, ["payload", "approvals"]) || !envelope.payload || typeof envelope.payload !== "object" || Array.isArray(envelope.payload)) return false;
  const payload = envelope.payload as Record<string, unknown>;
  if (!exact(payload, ["schema", "kind", "repository_id", "approval_id", "go_sha256", "sequence", "status", "valid_from", "valid_until"])
      || payload.schema !== 1 || payload.kind !== "F4_REVOCATION_STATUS" || payload.repository_id !== REPOSITORY_ID
      || typeof payload.approval_id !== "string" || !payload.approval_id
      || typeof payload.go_sha256 !== "string" || !shaPattern.test(payload.go_sha256)
      || !Number.isSafeInteger(payload.sequence) || (payload.status !== "ACTIVE" && payload.status !== "REVOKED" && payload.status !== "STOPPED")) return false;
  const approvals = envelope.approvals as Record<string, unknown>;
  if (!approvals || typeof approvals !== "object" || Array.isArray(approvals) || !exact(approvals, ["owner_a", "owner_b"])) return false;
  const ownerA = approvals.owner_a as Record<string, unknown>;
  const ownerB = approvals.owner_b as Record<string, unknown>;
  return [ownerA, ownerB].every((item) => item && typeof item === "object" && !Array.isArray(item)
      && exact(item, ["key_id", "signature", "payload"])
      && typeof item.key_id === "string" && Boolean(item.key_id)
      && typeof item.signature === "string" && /^[A-Za-z0-9+/]{86}==$/.test(item.signature)
      && canonical(item.payload) === canonical(payload))
    && ownerA.key_id !== ownerB.key_id;
}

type VerificationKey = { key_id: string; role: string; public_key: Uint8Array };

async function verifyStoredSignatures(document: Record<string, unknown>, env: CasDependencies["env"]): Promise<void> {
  const ownerKeys = loadOwnerKeys(env);
  const auditorKey = loadAuditorKey(env, ownerKeys);
  const events = document.events as Array<{ payload: Record<string, unknown> }>;
  for (const entry of events) {
    const event = entry.payload;
    if (event.event === "CONTROL_CREATED" || event.event === "REVOCATION_STATUS") {
      const envelope = event.revocation_status as Record<string, unknown>;
      const payload = envelope?.payload as Record<string, unknown>;
      const approvals = envelope?.approvals as Record<string, Record<string, unknown>>;
      for (const role of ["owner_a", "owner_b"] as const) {
        const approval = approvals?.[role];
        const key = approval && ownerKeys.get(String(approval.key_id));
        if (!key || key.role !== role || !await verifyEnvelope(approval, key, payload)) {
          throw new Error("owner_signature_invalid");
        }
      }
      const validFrom = Date.parse(String(payload.valid_from ?? ""));
      const validUntil = Date.parse(String(payload.valid_until ?? ""));
      if (!Number.isFinite(validFrom) || !Number.isFinite(validUntil)
          || validUntil <= validFrom || Date.now() < validFrom || Date.now() >= validUntil
          || payload.approval_id !== document.approval_id || payload.go_sha256 !== document.go_sha256) {
        throw new Error("owner_revocation_scope_or_validity_invalid");
      }
    }
    if (event.event === "CYCLE1_AUDITOR_PASS") {
      const envelope = event.auditor_envelope as Record<string, unknown>;
      const payload = envelope?.payload as Record<string, unknown>;
      if (!await verifyEnvelope(envelope, auditorKey, payload)
          || !validAuditorPayload(payload, document, event)
          || await sha256(canonical(envelope)) !== event.artifact_envelope_sha256) {
        throw new Error("auditor_signature_invalid");
      }
    }
  }
}

function loadOwnerKeys(env: CasDependencies["env"]): Map<string, VerificationKey> {
  const raw = env.get("B09_F4_TRUSTED_KEYS_JSON") ?? "";
  if (!raw) throw new Error("trusted_owner_keys_missing");
  let document: unknown;
  try { document = JSON.parse(raw); } catch { throw new Error("trusted_owner_keys_invalid"); }
  if (!document || typeof document !== "object" || Array.isArray(document)
      || !exact(document as Record<string, unknown>, ["keys"])) throw new Error("trusted_owner_keys_invalid");
  const entries = (document as { keys?: unknown }).keys;
  if (!Array.isArray(entries) || entries.length !== 4) throw new Error("trusted_owner_keys_invalid");
  const keys = new Map<string, VerificationKey>();
  const roles = new Set<string>();
  const publicKeys = new Set<string>();
  for (const item of entries) {
    if (!item || typeof item !== "object" || Array.isArray(item)
        || !exact(item as Record<string, unknown>, ["key_id", "role", "public_key"])) throw new Error("trusted_owner_keys_invalid");
    const entry = item as Record<string, unknown>;
    if (typeof entry.key_id !== "string" || !entry.key_id || keys.has(entry.key_id)
        || !["permit_authority", "witness", "owner_a", "owner_b"].includes(String(entry.role))
        || roles.has(String(entry.role)) || typeof entry.public_key !== "string") throw new Error("trusted_owner_keys_invalid");
    const publicKey = decodeBase64(entry.public_key);
    const fingerprint = Array.from(publicKey).join(",");
    if (publicKey.length !== 32 || publicKeys.has(fingerprint)) throw new Error("trusted_owner_keys_not_independent");
    keys.set(entry.key_id, { key_id: entry.key_id, role: String(entry.role), public_key: publicKey });
    roles.add(String(entry.role));
    publicKeys.add(fingerprint);
  }
  return keys;
}

function loadAuditorKey(env: CasDependencies["env"], ownerKeys: Map<string, VerificationKey>): VerificationKey {
  const raw = env.get("B09_F4_AUDITOR_KEY_JSON") ?? "";
  if (!raw) throw new Error("trusted_auditor_key_missing");
  let document: unknown;
  try { document = JSON.parse(raw); } catch { throw new Error("trusted_auditor_key_invalid"); }
  if (!document || typeof document !== "object" || Array.isArray(document)
      || !exact(document as Record<string, unknown>, ["key_id", "role", "public_key"])) throw new Error("trusted_auditor_key_invalid");
  const entry = document as Record<string, unknown>;
  if (typeof entry.key_id !== "string" || !entry.key_id || entry.role !== "auditor"
      || typeof entry.public_key !== "string" || ownerKeys.has(entry.key_id)) throw new Error("trusted_auditor_key_invalid");
  const publicKey = decodeBase64(entry.public_key);
  if (publicKey.length !== 32 || [...ownerKeys.values()].some((key) => constantEqualBytes(key.public_key, publicKey))) {
    throw new Error("trusted_auditor_key_not_independent");
  }
  return { key_id: entry.key_id, role: "auditor", public_key: publicKey };
}

async function verifyEnvelope(envelope: Record<string, unknown>, key: VerificationKey,
  expectedPayload: Record<string, unknown>): Promise<boolean> {
  if (!envelope || !exact(envelope, ["key_id", "signature", "payload"])
      || envelope.key_id !== key.key_id || canonical(envelope.payload) !== canonical(expectedPayload)
      || typeof envelope.signature !== "string") return false;
  try {
    const signature = decodeBase64(envelope.signature);
    if (signature.length !== 64) return false;
    const cryptoKey = await crypto.subtle.importKey("raw", key.public_key, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, signature, encoder.encode(canonical(expectedPayload)));
  } catch { return false; }
}

function validAuditorPayload(payload: Record<string, unknown>, document: Record<string, unknown>, event: Record<string, unknown>): boolean {
  const now = Date.now();
  const issued = Date.parse(String(payload.issued_at ?? ""));
  const expires = Date.parse(String(payload.expires_at ?? ""));
  return exact(payload, auditPayloadFields) && payload.schema === 1 && payload.kind === "F4_CYCLE_AUDIT"
    && payload.repository_id === REPOSITORY_ID && payload.approval_id === document.approval_id
    && payload.go_sha256 === document.go_sha256 && payload.base_sha === document.base_sha
    && payload.cycle_number === 1 && payload.result === "PASS"
    && payload.worker_run_id === event.worker_run_id && payload.auditor_run_id === event.auditor_run_id
    && payload.workflow_run_id === event.workflow_run_id && payload.run_attempt === event.run_attempt
    && payload.source_commit_sha === event.source_commit_sha && payload.workflow_path === AUDIT_WORKFLOW_PATH
    && payload.pr_number === 1 && payload.pr_state === "open" && payload.pr_is_draft === true
    && payload.pr_merged === false && payload.pr_base_sha === document.base_sha
    && payload.readonly_ci_conclusion === "success"
    && typeof payload.pr_head_sha === "string" && gitPattern.test(payload.pr_head_sha)
    && typeof payload.readonly_ci_run_id === "string" && /^\d+$/.test(payload.readonly_ci_run_id)
    && typeof payload.candidate_digest === "string" && shaPattern.test(payload.candidate_digest)
    && typeof payload.witness_digest === "string" && shaPattern.test(payload.witness_digest)
    && typeof payload.journal_head_sha256 === "string" && shaPattern.test(payload.journal_head_sha256)
    && Number.isSafeInteger(payload.journal_revision) && Number(payload.journal_revision) > 0
    && Number.isFinite(issued) && Number.isFinite(expires) && issued <= now && now < expires;
}

function decodeBase64(value: string): Uint8Array {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error("base64_invalid");
  const bytes = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  if (btoa(String.fromCharCode(...bytes)) !== value) throw new Error("base64_invalid");
  return bytes;
}

function constantEqualBytes(left: Uint8Array, right: Uint8Array): boolean {
  let diff = left.length ^ right.length;
  for (let i = 0; i < Math.max(left.length, right.length); i++) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}

async function readBounded(request: Request, limit: number): Promise<Uint8Array> {
  const reader = request.body?.getReader();
  if (!reader) throw new Error("empty_body");
  const chunks: Uint8Array[] = []; let total = 0;
  while (true) { const { done, value } = await reader.read(); if (done) break; total += value.byteLength; if (total > limit) { await reader.cancel(); throw new Error("body_too_large"); } chunks.push(value); }
  if (!total) throw new Error("empty_body");
  const bytes = new Uint8Array(total); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}
function canonical(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isSafeInteger(value)) throw new Error("number_invalid"); return JSON.stringify(value); }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonical((value as Record<string, unknown>)[key])).join(",") + "}";
  throw new Error("json_invalid");
}
async function sha256(value: string): Promise<string> { const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(value)); return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join(""); }
function exact(value: Record<string, unknown>, keys: string[]): boolean { const actual = Object.keys(value).sort(); const expected = [...keys].sort(); return actual.length === expected.length && actual.every((key, i) => key === expected[i]); }
function etag(revision: number): string { return `"${revision}"`; }
function response(status: number): Response { return new Response(null, { status, headers: { "cache-control": "no-store" } }); }
function constantEqual(left: string, right: string): boolean { const a = encoder.encode(left); const b = encoder.encode(right); let diff = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0); return diff === 0; }

/** Pure request and journal boundary; no Supabase or network side effects. */
export const CAS_KEY = "repositories/1458303357/b09-permit-journal-v1.json";
export const RETIRED_CAS_TEST_KEY = "repositories/1458303357/b09-permit-journal-test-v1.json";
export const REPOSITORY_ID = 1458303357;
export const MAX_DOCUMENT_BYTES = 1024 * 1024;
export const CAS_AUTH_GENERATION = "v2";
export const CAS_AUTH_GENERATION_ENV = "B09_CAS_AUTH_GENERATION";
export const CAS_AUTH_GENERATION_HEADER = "x-b09-cas-auth-generation";

export const PERMIT_TOKEN_ENV = {
  issuer: "B09_CAS_V2_ISSUER_BEARER",
  witness: "B09_CAS_V2_WITNESS_BEARER",
  publisher: "B09_CAS_V2_PUBLISHER_BEARER",
  auditor: "B09_CAS_V2_AUDITOR_BEARER",
} as const;
export const F4_TOKEN_ENV = {
  owner: "B09_F4_CONTROL_V2_OWNER_BEARER",
  worker: "B09_F4_CONTROL_V2_WORKER_BEARER",
  auditor: "B09_F4_CONTROL_V2_AUDITOR_BEARER",
  read: "B09_F4_CONTROL_V2_READ_BEARER",
  testOwner: "B09_F4_CONTROL_V2_TEST_OWNER_BEARER",
  testWorker: "B09_F4_CONTROL_V2_TEST_WORKER_BEARER",
  testAuditor: "B09_F4_CONTROL_V2_TEST_AUDITOR_BEARER",
  testRead: "B09_F4_CONTROL_V2_TEST_READ_BEARER",
} as const;
const RETIRED_TOKEN_ENV_NAMES = [
  "B09_CAS_ISSUER_BEARER", "B09_CAS_WITNESS_BEARER", "B09_CAS_TOKEN", "B09_CAS_READ_TOKEN",
  "B09_CAS_TEST_ISSUER_BEARER", "B09_CAS_TEST_WITNESS_BEARER",
  "B09_CAS_TEST_PUBLISHER_BEARER", "B09_CAS_TEST_AUDITOR_BEARER",
  "B09_CAS_V2_TEST_ISSUER_BEARER", "B09_CAS_V2_TEST_WITNESS_BEARER",
  "B09_CAS_V2_TEST_PUBLISHER_BEARER", "B09_CAS_V2_TEST_AUDITOR_BEARER",
  "B09_F4_CONTROL_OWNER_BEARER", "B09_F4_CONTROL_WORKER_BEARER",
  "B09_F4_CONTROL_AUDITOR_BEARER", "B09_F4_CONTROL_READ_BEARER",
  "B09_F4_TEST_CONTROL_OWNER_BEARER", "B09_F4_TEST_CONTROL_WORKER_BEARER",
  "B09_F4_TEST_CONTROL_AUDITOR_BEARER", "B09_F4_TEST_CONTROL_READ_BEARER",
] as const;
const V2_TOKEN_ENV_NAMES = [
  ...Object.values(PERMIT_TOKEN_ENV),
  ...Object.values(F4_TOKEN_ENV),
] as const;
type Credential = keyof typeof PERMIT_TOKEN_ENV;
type Role = "issuer" | "witness" | "publisher" | "auditor";

export interface CasStoredDocument {
  revision: number;
  body: string;
}

export interface CasStore {
  read(key: string): Promise<CasStoredDocument | undefined>;
  insertIfAbsent(key: string, body: string): Promise<number | undefined>;
  updateIfRevision(key: string, revision: number, body: string): Promise<number | undefined>;
}

export interface CasDependencies {
  env: { get(name: string): string | undefined };
  store: CasStore | null;
}

type JournalPayload = Record<string, unknown>;
type JournalEvent = {
  sequence: number;
  previous_sha256: string;
  payload: JournalPayload;
  event_sha256: string;
};
type Journal = {
  schema: 1;
  repository_id: number;
  sequence: number;
  head_sha256: string;
  events: JournalEvent[];
};

const encoder = new TextEncoder();
const shaPattern = /^[0-9a-f]{64}$/;
const formalPaths = new Set([
  "/functions/v1/sake-cas-v1/" + CAS_KEY,
  "/" + CAS_KEY,
]);
const retiredTestPaths = new Set([
  "/functions/v1/sake-cas-v1/" + RETIRED_CAS_TEST_KEY,
  "/" + RETIRED_CAS_TEST_KEY,
]);

export async function handleCasRequest(
  request: Request,
  dependencies: CasDependencies,
): Promise<Response> {
  const pathname = new URL(request.url).pathname;
  if (retiredTestPaths.has(pathname)) return response(410);
  const authGenerationFailure = casAuthGenerationFailure(request, dependencies.env);
  if (authGenerationFailure !== null) return response(authGenerationFailure);
  const tokens = readRoleTokens(dependencies.env);
  if (!tokens) return response(503);

  const principal = identifyPrincipal(request.headers.get("authorization"), tokens);
  if (!principal) return response(401);
  if (!dependencies.store) return response(503);

  if (!formalPaths.has(pathname)) return response(404);
  const key = CAS_KEY;

  if (request.method === "GET") {
    try {
      const stored = await dependencies.store.read(key);
      if (!stored) return response(404);
      if (!Number.isSafeInteger(stored.revision) || stored.revision < 1) return response(503);
      const parsed = await parseJournal(encoder.encode(stored.body));
      if (parsed.repository_id !== REPOSITORY_ID || parsed.sequence !== stored.revision) {
        return response(503);
      }
      return new Response(stored.body, {
        status: 200,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
          etag: etag(stored.revision),
        },
      });
    } catch {
      return response(503);
    }
  }

  if (request.method !== "PUT") {
    return new Response(null, { status: 405, headers: { allow: "GET, PUT" } });
  }
  if (principal !== "issuer" && principal !== "publisher") return response(403);
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)) {
    return response(415);
  }

  const ifMatch = request.headers.get("if-match");
  const ifNoneMatch = request.headers.get("if-none-match");
  if ((ifMatch === null) === (ifNoneMatch === null)) return response(428);
  if (ifNoneMatch !== null && ifNoneMatch !== "*") return response(412);

  let bodyBytes: Uint8Array;
  let bodyText: string;
  let nextJournal: Journal;
  try {
    bodyBytes = await readBoundedBody(request, MAX_DOCUMENT_BYTES);
    bodyText = new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes);
    nextJournal = await parseJournal(bodyBytes);
  } catch {
    return response(409);
  }

  let current: CasStoredDocument | undefined;
  try {
    current = await dependencies.store.read(key);
  } catch {
    return response(503);
  }

  if (current === undefined) {
    if (ifMatch !== null) return response(412);
    if (principal !== "issuer") return response(403);
    try {
      validateFirstIssuance(nextJournal, principal);
    } catch {
      return response(409);
    }
    try {
      const revision = await dependencies.store.insertIfAbsent(key, bodyText);
      return revision === undefined ? response(412) : etagResponse(revision);
    } catch {
      return response(503);
    }
  }

  if (ifMatch === null || ifMatch !== etag(current.revision)) return response(412);
  let previousJournal: Journal;
  try {
    previousJournal = await parseJournal(encoder.encode(current.body));
    validateAppend(previousJournal, nextJournal, principal);
  } catch {
    return response(409);
  }
  try {
    const revision = await dependencies.store.updateIfRevision(
      key,
      current.revision,
      bodyText,
    );
    return revision === undefined ? response(412) : etagResponse(revision);
  } catch {
    // Unknown database outcome is deliberately not retried.
    return response(503);
  }
}

function readRoleTokens(env: CasDependencies["env"]): Record<Credential, string> | null {
  const all = readV2RoleTokens(env);
  if (!all) return null;
  return {
    issuer: all[PERMIT_TOKEN_ENV.issuer],
    witness: all[PERMIT_TOKEN_ENV.witness],
    publisher: all[PERMIT_TOKEN_ENV.publisher],
    auditor: all[PERMIT_TOKEN_ENV.auditor],
  };
}

export function readV2RoleTokens(
  env: CasDependencies["env"],
): Record<(typeof V2_TOKEN_ENV_NAMES)[number], string> | null {
  if (RETIRED_TOKEN_ENV_NAMES.some((name) => env.get(name) !== undefined)) return null;
  const tokens = Object.fromEntries(
    V2_TOKEN_ENV_NAMES.map((name) => [name, env.get(name) ?? ""]),
  ) as Record<(typeof V2_TOKEN_ENV_NAMES)[number], string>;
  const values = Object.values(tokens);
  if (values.some((value) => encoder.encode(value).length < 32)) return null;
  for (let i = 0; i < values.length; i++) {
    for (let j = i + 1; j < values.length; j++) {
      if (constantTimeEqual(values[i], values[j])) return null;
    }
  }
  return tokens;
}

export function casAuthGenerationFailure(
  request: Request,
  env: CasDependencies["env"],
): 401 | 503 | null {
  if (env.get(CAS_AUTH_GENERATION_ENV) !== CAS_AUTH_GENERATION) return 503;
  if (request.headers.get(CAS_AUTH_GENERATION_HEADER) !== CAS_AUTH_GENERATION) return 401;
  return null;
}

function identifyPrincipal(
  authorization: string | null,
  tokens: Record<Credential, string>,
): Role | null {
  if (!authorization?.startsWith("Bearer ")) return null;
  const candidate = authorization.slice(7);
  let matched: Credential | null = null;
  for (const credential of Object.keys(PERMIT_TOKEN_ENV) as Credential[]) {
    if (constantTimeEqual(candidate, tokens[credential])) matched = credential;
  }
  if (!matched) return null;
  return matched as Role;
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return difference === 0;
}

async function readBoundedBody(request: Request, limit: number): Promise<Uint8Array> {
  const reader = request.body?.getReader();
  if (!reader) throw new Error("empty_body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      throw new Error("body_too_large");
    }
    chunks.push(value);
  }
  if (total === 0) throw new Error("empty_body");
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function parseJournal(bytes: Uint8Array): Promise<Journal> {
  const document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!isObject(document) || !hasExactKeys(document, [
    "schema", "repository_id", "sequence", "head_sha256", "events",
  ])) throw new Error("document_shape_invalid");
  if (document.schema !== 1 || document.repository_id !== REPOSITORY_ID
      || !Number.isSafeInteger(document.sequence) || !Array.isArray(document.events)
      || !isSha(document.head_sha256)) throw new Error("document_scope_invalid");

  let previous = "0".repeat(64);
  for (let index = 0; index < document.events.length; index++) {
    const event = document.events[index];
    if (!isObject(event) || !hasExactKeys(event, [
      "sequence", "previous_sha256", "payload", "event_sha256",
    ]) || !Number.isSafeInteger(event.sequence) || event.sequence !== index + 1
        || event.previous_sha256 !== previous || !isObject(event.payload)
        || !isSha(event.event_sha256)) throw new Error("event_shape_invalid");
    validatePayload(event.payload);
    const eventBody = {
      sequence: event.sequence,
      previous_sha256: event.previous_sha256,
      payload: event.payload,
    };
    const digest = await sha256(canonical(eventBody));
    if (event.event_sha256 !== digest) throw new Error("journal_chain_invalid");
    previous = digest;
  }
  if (document.sequence !== document.events.length || document.head_sha256 !== previous) {
    throw new Error("journal_head_invalid");
  }
  return document as Journal;
}

function validatePayload(payload: JournalPayload): void {
  const eventType = payload.event;
  const expected = eventType === "PERMIT_ISSUED"
    ? ["event", "permit_id", "candidate_digest", "permit_digest", "worker_run_id"]
    : eventType === "PERMIT_CONSUMED"
    ? ["event", "permit_id", "candidate_digest", "permit_digest", "witness_digest", "worker_run_id"]
    : null;
  if (!expected || !hasExactKeys(payload, expected)
      || !isNonemptyText(payload.permit_id) || !isNonemptyText(payload.worker_run_id)
      || payload.permit_id.startsWith("TEST:") || payload.worker_run_id.startsWith("TEST:")
      || !isSha(payload.candidate_digest) || !isSha(payload.permit_digest)
      || (eventType === "PERMIT_CONSUMED" && !isSha(payload.witness_digest))) {
    throw new Error("journal_payload_invalid");
  }
}

function validateFirstIssuance(journal: Journal, role: Role): void {
  if (journal.events.length !== 1
      || role !== "issuer"
      || journal.events[0].payload.event !== "PERMIT_ISSUED") {
    throw new Error("initial_event_must_be_issuance");
  }
}

function validateAppend(previous: Journal, next: Journal, role: Role): void {
  if (next.events.length !== previous.events.length + 1
      || next.sequence !== previous.sequence + 1
      || next.repository_id !== previous.repository_id
      || next.events.slice(0, previous.events.length).some((event, index) =>
        canonical(event) !== canonical(previous.events[index])
      )) throw new Error("journal_not_append_only");

  const appended = next.events[next.events.length - 1].payload;
  if (role === "issuer") {
    if (appended.event !== "PERMIT_ISSUED"
        || previous.events.some((event) => event.payload.permit_id === appended.permit_id)) {
      throw new Error("issuer_scope_violation");
    }
    return;
  }
  if (role !== "publisher" || appended.event !== "PERMIT_CONSUMED") {
    throw new Error("role_cannot_append_event");
  }
  const history = previous.events.filter((event) =>
    event.payload.permit_id === appended.permit_id
  );
  const issuances = history.filter((event) => event.payload.event === "PERMIT_ISSUED");
  const consumptions = history.filter((event) => event.payload.event === "PERMIT_CONSUMED");
  if (issuances.length !== 1 || consumptions.length !== 0) {
    throw new Error("permit_missing_or_already_consumed");
  }
  const issued = issuances[0].payload;
  if (appended.candidate_digest !== issued.candidate_digest
      || appended.permit_digest !== issued.permit_digest
      || appended.worker_run_id !== issued.worker_run_id) {
    throw new Error("consumption_scope_mismatch");
  }
}

function canonical(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("non_integer_number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (isObject(value)) {
    return "{" + Object.keys(value).sort().map((key) =>
      JSON.stringify(key) + ":" + canonical(value[key])
    ).join(",") + "}";
  }
  throw new Error("unsupported_json_value");
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return keys.length === sortedExpected.length
    && keys.every((key, index) => key === sortedExpected[index]);
}

function isObject(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isSha(value: unknown): value is string {
  return typeof value === "string" && shaPattern.test(value);
}

function isNonemptyText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 200;
}

function etag(revision: number): string {
  return "\"" + revision + "\"";
}

function etagResponse(revision: number): Response {
  return new Response(null, {
    status: 204,
    headers: { etag: etag(revision), "cache-control": "no-store" },
  });
}

function response(status: number): Response {
  return new Response(null, { status, headers: { "cache-control": "no-store" } });
}

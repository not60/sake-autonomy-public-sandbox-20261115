import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  CAS_KEY,
  CAS_TEST_KEY,
  MAX_DOCUMENT_BYTES,
  handleCasRequest,
} from "../supabase/functions/sake-cas-v1/core.ts";

const tokens = {
  B09_CAS_V2_ISSUER_BEARER: "fixture-v2-issuer-token-0123456789-abcdef",
  B09_CAS_V2_WITNESS_BEARER: "fixture-v2-witness-token-0123456789-abcde",
  B09_CAS_V2_PUBLISHER_BEARER: "fixture-v2-publisher-token-0123456789-abcd",
  B09_CAS_V2_AUDITOR_BEARER: "fixture-v2-auditor-token-0123456789-abcdefg",
  B09_CAS_V2_TEST_ISSUER_BEARER: "fixture-v2-test-issuer-token-0123456789-abcdef",
  B09_CAS_V2_TEST_WITNESS_BEARER: "fixture-v2-test-witness-token-0123456789-abcde",
  B09_CAS_V2_TEST_PUBLISHER_BEARER: "fixture-v2-test-publisher-token-0123456789-abcd",
  B09_CAS_V2_TEST_AUDITOR_BEARER: "fixture-v2-test-auditor-token-0123456789-abcdefg",
};
const roleTokens = {
  issuer: "B09_CAS_V2_ISSUER_BEARER",
  witness: "B09_CAS_V2_WITNESS_BEARER",
  publisher: "B09_CAS_V2_PUBLISHER_BEARER",
  auditor: "B09_CAS_V2_AUDITOR_BEARER",
  testIssuer: "B09_CAS_V2_TEST_ISSUER_BEARER",
  testWitness: "B09_CAS_V2_TEST_WITNESS_BEARER",
  testPublisher: "B09_CAS_V2_TEST_PUBLISHER_BEARER",
  testAuditor: "B09_CAS_V2_TEST_AUDITOR_BEARER",
};

class FixtureStore {
  value;
  reads = 0;
  inserts = 0;
  updates = 0;
  failNextWrite = false;

  async read(key) {
    assert.equal(key, CAS_KEY);
    this.reads++;
    return this.value && { ...this.value };
  }

  async insertIfAbsent(key, body) {
    assert.equal(key, CAS_KEY);
    this.inserts++;
    if (this.failNextWrite) throw new Error("fixture_db_failure");
    if (this.value) return undefined;
    this.value = { revision: 1, body };
    return 1;
  }

  async updateIfRevision(key, revision, body) {
    assert.equal(key, CAS_KEY);
    this.updates++;
    if (this.failNextWrite) throw new Error("fixture_db_failure");
    if (!this.value || this.value.revision !== revision) return undefined;
    this.value = { revision: revision + 1, body };
    return revision + 1;
  }
}

class ScopedFixtureStore {
  values = new Map();
  reads = 0;
  inserts = 0;
  updates = 0;

  async read(key) {
    this.reads++;
    const value = this.values.get(key);
    return value && { ...value };
  }

  async insertIfAbsent(key, body) {
    this.inserts++;
    if (this.values.has(key)) return undefined;
    this.values.set(key, { revision: 1, body });
    return 1;
  }

  async updateIfRevision(key, revision, body) {
    this.updates++;
    const current = this.values.get(key);
    if (!current || current.revision !== revision) return undefined;
    this.values.set(key, { revision: revision + 1, body });
    return revision + 1;
  }
}

function deps(store, overrides = {}) {
  const values = { B09_CAS_AUTH_GENERATION: "v2", ...tokens, ...overrides };
  return { env: { get: (name) => values[name] }, store };
}

function request(method, role, options = {}) {
  const { body, headers = {}, path = "/functions/v1/sake-cas-v1/" + CAS_KEY,
    authGeneration = "v2" } = options;
  const token = role ? tokens[roleTokens[role]] : null;
  const requestHeaders = new Headers(headers);
  if (token) requestHeaders.set("authorization", "Bearer " + token);
  if (authGeneration !== null) requestHeaders.set("x-b09-cas-auth-generation", authGeneration);
  return new Request("https://fixture.invalid" + path, {
    method,
    headers: requestHeaders,
    body,
  });
}

async function makeJournal(events) {
  let previous = "0".repeat(64);
  const output = [];
  for (let index = 0; index < events.length; index++) {
    const eventBody = {
      sequence: index + 1,
      previous_sha256: previous,
      payload: events[index],
    };
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonical(eventBody)),
    );
    previous = Array.from(new Uint8Array(digest))
      .map((byte) => byte.toString(16).padStart(2, "0")).join("");
    output.push({ ...eventBody, event_sha256: previous });
  }
  return JSON.stringify({
    schema: 1,
    repository_id: 1458303357,
    sequence: output.length,
    head_sha256: previous,
    events: output,
  });
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.keys(value).sort().map((key) =>
    JSON.stringify(key) + ":" + canonical(value[key])
  ).join(",") + "}";
}

const issuedPayload = {
  event: "PERMIT_ISSUED",
  permit_id: "fixture-permit-1",
  candidate_digest: "a".repeat(64),
  permit_digest: "b".repeat(64),
  worker_run_id: "fixture-run-1",
};
const consumedPayload = {
  event: "PERMIT_CONSUMED",
  permit_id: "fixture-permit-1",
  candidate_digest: "a".repeat(64),
  permit_digest: "b".repeat(64),
  witness_digest: "c".repeat(64),
  worker_run_id: "fixture-run-1",
};

test("Issuer insert and independent role GET follow the existing ETag contract", async () => {
  const store = new FixtureStore();
  const body = await makeJournal([issuedPayload]);
  const response = await handleCasRequest(
    request("PUT", "issuer", {
      body,
      headers: { "if-none-match": "*", "content-type": "application/json" },
    }),
    deps(store),
  );
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("etag"), '"1"');
  for (const role of ["issuer", "witness", "publisher", "auditor"]) {
    const read = await handleCasRequest(request("GET", role), deps(store));
    assert.equal(read.status, 200);
    assert.equal(read.headers.get("etag"), '"1"');
    assert.equal(await read.text(), body);
  }
});

test("role credentials are distinct; missing and rejected credentials fail closed", async () => {
  const store = new FixtureStore();
  assert.equal((await handleCasRequest(request("GET", null), deps(store))).status, 401);
  assert.equal((await handleCasRequest(request("GET", "auditor"), deps(store, {
    B09_CAS_V2_AUDITOR_BEARER: tokens.B09_CAS_V2_WITNESS_BEARER,
  }))).status, 503);
  assert.equal((await handleCasRequest(request("GET", "auditor"), deps(store, {
    B09_CAS_V2_AUDITOR_BEARER: "",
  }))).status, 503);
  assert.equal(store.reads, 0);
});

test("legacy Bearer-only and wrong auth generations are rejected before DB access", async () => {
  const store = new FixtureStore();
  assert.equal((await handleCasRequest(request("GET", null, {
    headers: { authorization: "Bearer retired-permit-test-fixture" },
    authGeneration: null,
  }), deps(store))).status, 401);
  assert.equal((await handleCasRequest(request("GET", null, {
    headers: { authorization: "Bearer retired-permit-test-fixture" },
  }), deps(store))).status, 401);
  assert.equal((await handleCasRequest(request("GET", "testAuditor", {
    authGeneration: "v1",
  }), deps(store))).status, 401);
  assert.equal((await handleCasRequest(request("GET", "auditor"), deps(store, {
    B09_CAS_AUTH_GENERATION: "v1",
  }))).status, 503);
  assert.equal(store.reads, 0);
});

test("Witness and Auditor cannot write; role-specific event transitions are enforced", async () => {
  const store = new FixtureStore();
  const issued = await makeJournal([issuedPayload]);
  assert.equal((await handleCasRequest(request("PUT", "witness", {
    body: issued,
    headers: { "if-none-match": "*" },
  }), deps(store))).status, 403);
  assert.equal((await handleCasRequest(request("PUT", "auditor", {
    body: issued,
    headers: { "if-none-match": "*" },
  }), deps(store))).status, 403);
  assert.equal((await handleCasRequest(request("PUT", "publisher", {
    body: issued,
    headers: { "if-none-match": "*", "content-type": "application/json" },
  }), deps(store))).status, 403);
  assert.equal(store.inserts, 0);
});

test("stale ETag and concurrent old-revision updates reject without retry", async () => {
  const store = new FixtureStore();
  store.value = { revision: 1, body: await makeJournal([issuedPayload]) };
  const body = await makeJournal([issuedPayload, consumedPayload]);
  const headers = { "if-match": '"1"', "content-type": "application/json" };
  const first = await handleCasRequest(request("PUT", "publisher", { body, headers }), deps(store));
  const second = await handleCasRequest(request("PUT", "publisher", { body, headers }), deps(store));
  assert.equal(first.status, 204);
  assert.equal(second.status, 412);
  assert.equal(store.updates, 1);
  assert.equal(store.value.revision, 2);

  const replay = await makeJournal([issuedPayload, consumedPayload, consumedPayload]);
  const replayResult = await handleCasRequest(request("PUT", "publisher", {
    body: replay,
    headers: { "if-match": '"2"', "content-type": "application/json" },
  }), deps(store));
  assert.equal(replayResult.status, 409);
  assert.equal(store.updates, 1);
});

test("journal tampering, non-append replacement, and role-forged event fail closed", async () => {
  const store = new FixtureStore();
  const validIssued = await makeJournal([issuedPayload]);
  store.value = { revision: 1, body: validIssued };
  const tampered = JSON.parse(validIssued);
  tampered.events[0].payload.candidate_digest = "d".repeat(64);
  assert.equal((await handleCasRequest(request("GET", "auditor"), {
    env: { get: (name) => tokens[name] },
    store: { read: async () => ({ revision: 1, body: JSON.stringify(tampered) }) },
  })).status, 503);

  const replaced = await makeJournal([
    { ...issuedPayload, candidate_digest: "e".repeat(64) },
    consumedPayload,
  ]);
  assert.equal((await handleCasRequest(request("PUT", "publisher", {
    body: replaced,
    headers: { "if-match": '"1"', "content-type": "application/json" },
  }), deps(store))).status, 409);
  const forgedIssuerEvent = await makeJournal([issuedPayload, consumedPayload]);
  assert.equal((await handleCasRequest(request("PUT", "issuer", {
    body: forgedIssuerEvent,
    headers: { "if-match": '"1"', "content-type": "application/json" },
  }), deps(store))).status, 409);

  const reusedId = await makeJournal([
    issuedPayload,
    {
      ...issuedPayload,
      candidate_digest: "f".repeat(64),
      permit_digest: "1".repeat(64),
      worker_run_id: "fixture-run-2",
    },
  ]);
  assert.equal((await handleCasRequest(request("PUT", "issuer", {
    body: reusedId,
    headers: { "if-match": '"1"', "content-type": "application/json" },
  }), deps(store))).status, 409);
});

test("failed or ambiguous store write is held once and never retried", async () => {
  const store = new FixtureStore();
  store.value = { revision: 1, body: await makeJournal([issuedPayload]) };
  store.failNextWrite = true;
  const body = await makeJournal([issuedPayload, consumedPayload]);
  const result = await handleCasRequest(request("PUT", "publisher", {
    body,
    headers: { "if-match": '"1"', "content-type": "application/json" },
  }), deps(store));
  assert.equal(result.status, 503);
  assert.equal(store.updates, 1);
  assert.equal(store.value.revision, 1);
});

test("only the fixed formal and TEST keys plus GET/PUT methods are accepted", async () => {
  const store = new FixtureStore();
  assert.equal((await handleCasRequest(request("GET", "auditor", {
    path: "/other-key",
  }), deps(store))).status, 404);
  assert.equal((await handleCasRequest(request("DELETE", "auditor"), deps(store))).status, 405);
  assert.equal((await handleCasRequest(request("PUT", "issuer", {
    body: "{}",
    headers: { "if-none-match": "*", "content-type": "application/json" },
  }), deps(store))).status, 409);
  assert.equal(MAX_DOCUMENT_BYTES, 1024 * 1024);
  assert.equal(store.inserts, 0);
});

test("SQL candidate denies Data API roles and has revision-conditional atomic operations", async () => {
  const sql = await readFile(new URL("../schema.sql", import.meta.url), "utf8");
  assert.match(sql, /CREATE SCHEMA IF NOT EXISTS sake_cas_private/);
  assert.match(sql, /REVOKE ALL ON SCHEMA sake_cas_private FROM PUBLIC, anon, authenticated, service_role/);
  assert.match(sql, /ON CONFLICT \(cas_key\) DO NOTHING/);
  assert.match(sql, /WHERE cas_key = p_key AND revision = p_expected_revision/);
  assert.match(sql, /NOBYPASSRLS/);
  assert.match(sql, /b09-permit-journal-test-v1\.json/);
  assert.match(sql, /cas_key = ANY \(ARRAY/);
  assert.doesNotMatch(sql, /GRANT\s+[^;]*\bDELETE\b/i);
  assert.doesNotMatch(sql, /GRANT\s+[^;]*\bTRUNCATE\b/i);
});

test("Edge candidate matches existing CAS caller secret names and does not use service keys", async () => {
  const root = new URL("..", import.meta.url);
  const core = await readFile(new URL("../supabase/functions/sake-cas-v1/core.ts", import.meta.url), "utf8");
  const index = await readFile(new URL("../supabase/functions/sake-cas-v1/index.ts", import.meta.url), "utf8");
  const config = await readFile(new URL("../supabase/config.toml", import.meta.url), "utf8");
  assert.match(core, /B09_CAS_V2_PUBLISHER_BEARER/);
  assert.match(core, /B09_CAS_V2_AUDITOR_BEARER/);
  assert.match(core, /B09_CAS_V2_ISSUER_BEARER/);
  assert.match(core, /B09_CAS_V2_WITNESS_BEARER/);
  assert.match(core, /B09_CAS_V2_TEST_ISSUER_BEARER/);
  assert.match(core, /B09_CAS_V2_TEST_WITNESS_BEARER/);
  assert.match(core, /B09_CAS_V2_TEST_PUBLISHER_BEARER/);
  assert.match(core, /B09_CAS_V2_TEST_AUDITOR_BEARER/);
  assert.match(core, /B09_CAS_AUTH_GENERATION/);
  assert.doesNotMatch(core, /"B09_CAS_(?:ISSUER_BEARER|WITNESS_BEARER|TOKEN|READ_TOKEN|TEST_)/);
  assert.match(index, /B09_CAS_DB_URL/);
  assert.doesNotMatch(index, /SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY/);
  assert.doesNotMatch(index + core, /console\.(?:log|error|warn)/);
  assert.match(config, /verify_jwt = false/);
  assert.ok(root.pathname.endsWith("/supabase-cas-draft/"));
});

test("TEST scope rejects cross-key credentials before touching the CAS store", async () => {
  const store = new ScopedFixtureStore();
  const formalPath = "/functions/v1/sake-cas-v1/" + CAS_KEY;
  const testPath = "/functions/v1/sake-cas-v1/" + CAS_TEST_KEY;
  const testBody = await makeJournal([{
    ...issuedPayload,
    permit_id: "TEST:fixture-permit-cross-scope",
    worker_run_id: "TEST:fixture-run-cross-scope",
  }]);

  assert.equal((await handleCasRequest(request("GET", "testAuditor", {
    path: formalPath,
  }), deps(store))).status, 403);
  assert.equal((await handleCasRequest(request("GET", "auditor", {
    path: testPath,
  }), deps(store))).status, 403);
  assert.equal((await handleCasRequest(request("GET", "testAuditor", {
    path: "/functions/v1/sake-cas-v1/repositories/other/journal.json",
  }), deps(store))).status, 404);
  assert.equal((await handleCasRequest(request("PUT", "testIssuer", {
    path: formalPath,
    body: testBody,
    headers: { "if-none-match": "*", "content-type": "application/json" },
  }), deps(store))).status, 403);
  assert.equal((await handleCasRequest(request("PUT", "issuer", {
    path: testPath,
    body: testBody,
    headers: { "if-none-match": "*", "content-type": "application/json" },
  }), deps(store))).status, 403);
  assert.equal(store.reads, 0);
  assert.equal(store.inserts, 0);
});

test("TEST scope writes persist only the TEST key and require TEST Permit/run IDs", async () => {
  const store = new ScopedFixtureStore();
  const testPath = "/functions/v1/sake-cas-v1/" + CAS_TEST_KEY;
  const testIssued = {
    ...issuedPayload,
    permit_id: "TEST:fixture-permit-1",
    worker_run_id: "TEST:fixture-run-1",
  };
  const body = await makeJournal([testIssued]);
  const response = await handleCasRequest(request("PUT", "testIssuer", {
    body,
    path: testPath,
    headers: { "if-none-match": "*", "content-type": "application/json" },
  }), deps(store));

  assert.equal(response.status, 204);
  assert.equal(store.values.has(CAS_KEY), false);
  assert.equal(store.values.has(CAS_TEST_KEY), true);
  const testConsumed = {
    ...consumedPayload,
    permit_id: testIssued.permit_id,
    worker_run_id: testIssued.worker_run_id,
  };
  const appendedBody = await makeJournal([testIssued, testConsumed]);
  const appended = await handleCasRequest(request("PUT", "testPublisher", {
    body: appendedBody,
    path: testPath,
    headers: { "if-match": '"1"', "content-type": "application/json" },
  }), deps(store));
  assert.equal(appended.status, 204);
  assert.equal(appended.headers.get("etag"), '"2"');
  assert.equal((await handleCasRequest(request("GET", "testAuditor", {
    path: testPath,
  }), deps(store))).status, 200);
  assert.equal((await handleCasRequest(request("GET", "testWitness", {
    path: testPath,
  }), deps(store))).status, 200);
  assert.equal((await handleCasRequest(request("GET", "auditor"), deps(store))).status, 404);

  const badBody = await makeJournal([issuedPayload]);
  const rejected = await handleCasRequest(request("PUT", "testIssuer", {
    body: badBody,
    path: "/functions/v1/sake-cas-v1/" + CAS_TEST_KEY,
    headers: { "if-none-match": "*", "content-type": "application/json" },
  }), deps(new ScopedFixtureStore()));
  assert.equal(rejected.status, 409);

  const formalReject = await handleCasRequest(request("PUT", "issuer", {
    body,
    headers: { "if-none-match": "*", "content-type": "application/json" },
  }), deps(new ScopedFixtureStore()));
  assert.equal(formalReject.status, 409);
});

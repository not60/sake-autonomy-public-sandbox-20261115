import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  CAS_KEY,
  MAX_DOCUMENT_BYTES,
  RETIRED_CAS_TEST_KEY,
  handleCasRequest,
} from "../supabase/functions/sake-cas-v1/core.ts";

const tokens = {
  B09_CAS_V2_ISSUER_BEARER: "fixture-v2-issuer-token-0123456789-abcdef",
  B09_CAS_V2_WITNESS_BEARER: "fixture-v2-witness-token-0123456789-abcde",
  B09_CAS_V2_PUBLISHER_BEARER: "fixture-v2-publisher-token-0123456789-abcd",
  B09_CAS_V2_AUDITOR_BEARER: "fixture-v2-auditor-token-0123456789-abcdefg",
  B09_F4_CONTROL_V2_OWNER_BEARER: "fixture-f4-v2-owner-token-0123456789-abcde",
  B09_F4_CONTROL_V2_WORKER_BEARER: "fixture-f4-v2-worker-token-0123456789-abcde",
  B09_F4_CONTROL_V2_AUDITOR_BEARER: "fixture-f4-v2-auditor-token-0123456789-abcd",
  B09_F4_CONTROL_V2_READ_BEARER: "fixture-f4-v2-read-token-0123456789-abcdefg",
  B09_F4_CONTROL_V2_TEST_OWNER_BEARER: "fixture-f4-v2-test-owner-token-0123456789-abcde",
  B09_F4_CONTROL_V2_TEST_WORKER_BEARER: "fixture-f4-v2-test-worker-token-0123456789-abcde",
  B09_F4_CONTROL_V2_TEST_AUDITOR_BEARER: "fixture-f4-v2-test-auditor-token-0123456789-abcd",
  B09_F4_CONTROL_V2_TEST_READ_BEARER: "fixture-f4-v2-test-read-token-0123456789-abcdefg",
};
const roleTokens = {
  issuer: "B09_CAS_V2_ISSUER_BEARER",
  witness: "B09_CAS_V2_WITNESS_BEARER",
  publisher: "B09_CAS_V2_PUBLISHER_BEARER",
  auditor: "B09_CAS_V2_AUDITOR_BEARER",
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
  assert.equal((await handleCasRequest(request("GET", "auditor"), deps(store, {
    B09_F4_CONTROL_V2_WORKER_BEARER: tokens.B09_CAS_V2_ISSUER_BEARER,
  }))).status, 503);
  assert.equal((await handleCasRequest(request("GET", "auditor"), deps(store, {
    B09_CAS_TEST_ISSUER_BEARER: "retired-permit-test-fixture-secret-placeholder",
  }))).status, 503);
  for (const name of [
    "B09_CAS_V2_TEST_ISSUER_BEARER",
    "B09_CAS_V2_TEST_WITNESS_BEARER",
    "B09_CAS_V2_TEST_PUBLISHER_BEARER",
    "B09_CAS_V2_TEST_AUDITOR_BEARER",
  ]) {
    assert.equal((await handleCasRequest(request("GET", "auditor"), deps(store, {
      [name]: "retired-v2-permit-test-fixture-secret-placeholder",
    }))).status, 503);
  }
  assert.equal((await handleCasRequest(request("GET", null, {
    headers: { authorization: "Bearer " + tokens.B09_F4_CONTROL_V2_WORKER_BEARER },
  }), deps(store))).status, 401);
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

test("only the fixed formal key plus GET/PUT methods are accepted", async () => {
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

test("SQL candidates retain historic Permit TEST rows without granting executable access", async () => {
  const sql = await readFile(new URL("../schema.sql", import.meta.url), "utf8");
  const migration = await readFile(new URL("../migrations/20261119000100_f4_cycle_control.sql", import.meta.url), "utf8");
  const rollback = await readFile(new URL("../migrations/20261119000100_f4_cycle_control.rollback.sql", import.meta.url), "utf8");
  assert.match(sql, /CREATE SCHEMA IF NOT EXISTS sake_cas_private/);
  assert.match(sql, /REVOKE ALL ON SCHEMA sake_cas_private FROM PUBLIC, anon, authenticated, service_role/);
  assert.match(migration, /ON CONFLICT \(cas_key\) DO NOTHING/);
  assert.match(migration, /WHERE cas_key = p_key AND revision = p_expected_revision/);
  assert.match(sql, /NOBYPASSRLS/);
  assert.match(sql, /b09-permit-journal-test-v1\.json/);
  assert.match(migration, /b09-permit-journal-test-v1\.json/);
  const activePolicy = migration.split("CREATE POLICY b09_edge_fixed_key_only", 2)[1]
    .split("CREATE OR REPLACE FUNCTION", 1)[0];
  const activeRpcs = migration.split("CREATE OR REPLACE FUNCTION sake_cas_private.insert_if_absent", 2)[1];
  assert.doesNotMatch(activePolicy + activeRpcs, /b09-permit-journal-test-v1\.json/);
  assert.match(rollback, /b09-permit-journal-test-v1\.json/);
  const rollbackPolicy = rollback.split("CREATE POLICY b09_edge_fixed_key_only", 2)[1]
    .split("CREATE OR REPLACE FUNCTION", 1)[0];
  const rollbackRpcs = rollback.split("CREATE OR REPLACE FUNCTION sake_cas_private.insert_if_absent", 2)[1];
  assert.doesNotMatch(rollbackPolicy + rollbackRpcs, /b09-permit-journal-test-v1\.json/);
  assert.doesNotMatch(migration + rollback, /\b(?:DELETE\s+FROM|TRUNCATE|DROP\s+TABLE)\b/i);
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
  assert.match(core, /RETIRED_CAS_TEST_KEY/);
  const permitRegistry = core.split("export const PERMIT_TOKEN_ENV = {", 2)[1].split("} as const;", 1)[0];
  assert.doesNotMatch(permitRegistry, /B09_CAS_V2_TEST_(?:ISSUER|WITNESS|PUBLISHER|AUDITOR)_BEARER/);
  assert.match(core, /B09_CAS_V2_TEST_(?:ISSUER|WITNESS|PUBLISHER|AUDITOR)_BEARER/);
  assert.match(core, /B09_CAS_AUTH_GENERATION/);
  assert.match(core, /retiredTestPaths\.has\(pathname\).*response\(410\)/s);
  assert.match(core, /RETIRED_TOKEN_ENV_NAMES\.some\(\(name\) => env\.get\(name\) !== undefined\)/);
  assert.match(index, /B09_CAS_DB_URL/);
  assert.doesNotMatch(index, /CAS_TEST_KEY/);
  assert.doesNotMatch(index, /b09-permit-journal-test-v1\.json/);
  assert.doesNotMatch(index, /SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY/);
  assert.doesNotMatch(index + core, /console\.(?:log|error|warn)/);
  assert.match(config, /verify_jwt = false/);
  assert.ok(root.pathname.endsWith("/supabase-cas-draft/"));
});

test("retired Permit TEST paths reject every method, credential, and generation before DB access", async () => {
  const store = new FixtureStore();
  const paths = [
    "/functions/v1/sake-cas-v1/" + RETIRED_CAS_TEST_KEY,
    "/" + RETIRED_CAS_TEST_KEY,
  ];
  const methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
  const authValues = [
    null,
    "Bearer retired-old-generation-fixture",
    ...Object.values(tokens).map((value) => "Bearer " + value),
  ];
  const generations = [null, "v1", "v2"];

  for (const path of paths) {
    for (const method of methods) {
      for (const authorization of authValues) {
        for (const generation of generations) {
          const headers = new Headers();
          if (authorization !== null) headers.set("authorization", authorization);
          if (generation !== null) headers.set("x-b09-cas-auth-generation", generation);
          if (method === "PUT" || method === "POST" || method === "PATCH") {
            headers.set("content-type", "application/json");
          }
          const response = await handleCasRequest(new Request("https://fixture.invalid" + path, {
            method,
            headers,
            body: method === "PUT" || method === "POST" || method === "PATCH" ? "{}" : undefined,
          }), deps(store));
          assert.equal(response.status, 410, `${method} ${path} generation=${generation}`);
        }
      }
    }
  }
  assert.equal(store.reads, 0);
  assert.equal(store.inserts, 0);
  assert.equal(store.updates, 0);
});

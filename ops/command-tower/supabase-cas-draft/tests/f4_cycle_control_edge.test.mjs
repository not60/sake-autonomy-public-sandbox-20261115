import assert from "node:assert/strict";
import test from "node:test";
import { F4_CONTROL_KEY, F4_CONTROL_TEST_KEY, handleF4ControlRequest } from "../supabase/functions/sake-cas-v1/cycle_control.ts";

const names = [
  "B09_F4_CONTROL_V2_OWNER_BEARER", "B09_F4_CONTROL_V2_WORKER_BEARER", "B09_F4_CONTROL_V2_AUDITOR_BEARER", "B09_F4_CONTROL_V2_READ_BEARER",
  "B09_F4_CONTROL_V2_TEST_OWNER_BEARER", "B09_F4_CONTROL_V2_TEST_WORKER_BEARER", "B09_F4_CONTROL_V2_TEST_AUDITOR_BEARER", "B09_F4_CONTROL_V2_TEST_READ_BEARER",
];
const envValues = Object.fromEntries(names.map((name, i) => [name, `fixture-f4-control-v2-role-${i}-long-unique-token` ]));
for (const [i, name] of [
  "B09_CAS_V2_ISSUER_BEARER", "B09_CAS_V2_WITNESS_BEARER",
  "B09_CAS_V2_PUBLISHER_BEARER", "B09_CAS_V2_AUDITOR_BEARER",
].entries()) envValues[name] = `fixture-permit-v2-role-${i}-long-unique-token`;
envValues.B09_CAS_AUTH_GENERATION = "v2";
const b64 = (value) => btoa(String.fromCharCode(...new Uint8Array(value)));
const signingKeys = {};
for (const role of ["permit_authority", "witness", "owner_a", "owner_b", "auditor"]) {
  signingKeys[role] = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
}
const ownerKeyDocument = { keys: await Promise.all(["permit_authority", "witness", "owner_a", "owner_b"].map(async (role) => ({
  key_id: `${role}-key`, role,
  public_key: b64(await crypto.subtle.exportKey("raw", signingKeys[role].publicKey)),
}))) };
const auditorKeyDocument = {
  key_id: "auditor-key", role: "auditor",
  public_key: b64(await crypto.subtle.exportKey("raw", signingKeys.auditor.publicKey)),
};
envValues.B09_F4_TRUSTED_KEYS_JSON = JSON.stringify(ownerKeyDocument);
envValues.B09_F4_AUDITOR_KEY_JSON = JSON.stringify(auditorKeyDocument);
class Store {
  values = new Map();
  reads = 0;
  async read(key) { this.reads++; return this.values.get(key); }
  async insertIfAbsent(key, body) { if (this.values.has(key)) return undefined; this.values.set(key, { revision: 1, body }); return 1; }
  async updateIfRevision(key, revision, body) { const current = this.values.get(key); if (!current || current.revision !== revision) return undefined; this.values.set(key, { revision: revision + 1, body }); return revision + 1; }
}
const store = new Store();
const deps = { env: { get: (name) => envValues[name] }, store };
const token = (name) => envValues[name];
const auth = (name) => ({ authorization: `Bearer ${token(name)}`, "x-b09-cas-auth-generation": "v2" });
const canonical = (value) => value === null || typeof value !== "object"
  ? JSON.stringify(value)
  : Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
  : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
const hash = async (value) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(value)))), (b) => b.toString(16).padStart(2, "0")).join("");
function request(method, name, key = F4_CONTROL_KEY, options = {}) {
  const path = options.path ?? `/functions/v1/sake-cas-v1/${key}`;
  return new Request(`https://fixture.invalid${path}`, { method, headers: { ...auth(name), ...(options.headers ?? {}) }, body: options.body });
}
async function initialDocument() {
  const statusPayload = { schema: 1, kind: "F4_REVOCATION_STATUS", repository_id: 1458303357, approval_id: "f4-fixture", go_sha256: "a".repeat(64), sequence: 1, status: "ACTIVE", valid_from: new Date(Date.now() - 60_000).toISOString(), valid_until: new Date(Date.now() + 60 * 60_000).toISOString() };
  const status = { payload: statusPayload, approvals: {
    owner_a: await sign("owner_a", statusPayload),
    owner_b: await sign("owner_b", statusPayload),
  } };
  const eventBody = { sequence: 1, previous_sha256: "0".repeat(64), payload: { event: "CONTROL_CREATED", revocation_status: status } };
  const digest = await hash(eventBody);
  return { schema: 1, repository_id: 1458303357, approval_id: "f4-fixture", go_sha256: "a".repeat(64), base_sha: "b".repeat(40), go_revocation_sequence: 1, revocation_sequence: 1, sequence: 1, head_sha256: digest, events: [{ ...eventBody, event_sha256: digest }] };
}
async function sign(role, payload) {
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, signingKeys[role].privateKey, new TextEncoder().encode(canonical(payload)));
  return { key_id: `${role}-key`, signature: b64(signature), payload };
}
async function append(document, payload) {
  const body = { sequence: document.sequence + 1, previous_sha256: document.head_sha256, payload };
  const digest = await hash(body);
  const events = [...document.events, { ...body, event_sha256: digest }];
  return { ...document, sequence: events.length, head_sha256: digest, events };
}
async function rehashDocument(document) {
  let previous = "0".repeat(64);
  const events = [];
  for (const original of document.events) {
    const body = { sequence: events.length + 1, previous_sha256: previous, payload: original.payload };
    const digest = await hash(body);
    events.push({ ...body, event_sha256: digest });
    previous = digest;
  }
  return { ...document, events, sequence: events.length, head_sha256: previous,
    revocation_sequence: document.go_revocation_sequence };
}
function auditPayload(document) {
  return {
    schema: 1, kind: "F4_CYCLE_AUDIT", repository_id: 1458303357,
    approval_id: document.approval_id, go_sha256: document.go_sha256, cycle_number: 1,
    worker_run_id: "run-1", auditor_run_id: "auditor-1", workflow_run_id: "12345", run_attempt: 1,
    workflow_path: ".github/workflows/public-runner-draft.yml", source_commit_sha: "d".repeat(40),
    base_sha: document.base_sha, pr_number: 1, pr_state: "open", pr_is_draft: true, pr_merged: false,
    pr_head_sha: "e".repeat(40), pr_base_sha: document.base_sha, readonly_ci_run_id: "98765",
    readonly_ci_conclusion: "success", permit_id: "permit-1", candidate_digest: "a".repeat(64),
    witness_digest: "c".repeat(64), journal_revision: 2, journal_head_sha256: "d".repeat(64),
    result: "PASS", issued_at: new Date(Date.now() - 1000).toISOString(),
    expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
  };
}

test("fixed control keys, independent credentials, and role transitions fail closed", async () => {
  assert.equal(F4_CONTROL_KEY, "repositories/1458303357/b09-f4-cycle-control-v1.json");
  assert.equal(F4_CONTROL_TEST_KEY, "repositories/1458303357/b09-f4-cycle-control-test-v1.json");
  assert.equal((await handleF4ControlRequest(request("GET", "B09_F4_CONTROL_V2_READ_BEARER", "repositories/1458303357/other.json"), deps)).status, 404);
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_OWNER_BEARER", F4_CONTROL_TEST_KEY, { headers: { "content-type": "application/json", "if-none-match": "*" }, body: JSON.stringify(await initialDocument()) }), deps)).status, 403);
  const created = await initialDocument();
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_OWNER_BEARER", F4_CONTROL_KEY, { headers: { "content-type": "application/json", "if-none-match": "*" }, body: JSON.stringify(created) }), deps)).status, 204);
  const claim = await append(created, { event: "CYCLE_CLAIMED", cycle_number: 1, run_id: "run-1", go_sha256: created.go_sha256, revocation_sequence: 1, revocation_digest: "c".repeat(64), claimed_at: "2026-11-19T00:00:00Z", source_commit_sha: "d".repeat(40) });
  const headers = { "content-type": "application/json", "if-match": '"1"' };
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_AUDITOR_BEARER", F4_CONTROL_KEY, { headers, body: JSON.stringify(claim) }), deps)).status, 403);
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_WORKER_BEARER", F4_CONTROL_KEY, { headers, body: JSON.stringify(claim) }), deps)).status, 204);
  const cycle2 = await append(claim, { event: "CYCLE_CLAIMED", cycle_number: 2, run_id: "run-2", go_sha256: created.go_sha256, revocation_sequence: 1, revocation_digest: "c".repeat(64), claimed_at: "2026-11-19T00:00:00Z", source_commit_sha: "e".repeat(40) });
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_WORKER_BEARER", F4_CONTROL_KEY, { headers: { "content-type": "application/json", "if-match": '"2"' }, body: JSON.stringify(cycle2) }), deps)).status, 409);
  const auditorEnvelope = await sign("auditor", auditPayload(created));
  const audit = await append(claim, { event: "CYCLE1_AUDITOR_PASS", artifact_envelope_sha256: await hash(auditorEnvelope), artifact_id: 17, artifact_archive_digest: "sha256:" + "1".repeat(64), workflow_run_id: "12345", run_attempt: 1, worker_run_id: "run-1", auditor_run_id: "auditor-1", source_commit_sha: "d".repeat(40), auditor_envelope: auditorEnvelope });
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_AUDITOR_BEARER", F4_CONTROL_KEY, { headers: { "content-type": "application/json", "if-match": '"2"' }, body: JSON.stringify(audit) }), deps)).status, 204);
  const cycle2AfterAudit = await append(audit, cycle2.events[2].payload);
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_WORKER_BEARER", F4_CONTROL_KEY, { headers: { "content-type": "application/json", "if-match": '"3"' }, body: JSON.stringify(cycle2AfterAudit) }), deps)).status, 204);
  const wrongMode = await handleF4ControlRequest(request("GET", "B09_F4_CONTROL_V2_TEST_READ_BEARER", F4_CONTROL_KEY), deps);
  assert.equal(wrongMode.status, 403);
});

test("F4 handler accepts all fixed path aliases and rejects cross-mode or altered paths", async () => {
  const isolatedStore = new Store();
  const isolatedDeps = { env: { get: (name) => envValues[name] }, store: isolatedStore };
  const prefixes = [
    "/functions/v1/sake-cas-v1/",
    "/sake-cas-v1/",
    "/",
  ];

  for (const prefix of prefixes) {
    const aliasIndex = prefixes.indexOf(prefix);
    const formal = await handleF4ControlRequest(request(
      "GET", "B09_F4_CONTROL_V2_READ_BEARER", F4_CONTROL_KEY,
      { path: prefix + F4_CONTROL_KEY },
    ), isolatedDeps);
    assert.equal(formal.status, 404);
    assert.equal(isolatedStore.reads, aliasIndex * 2 + 1);

    const test = await handleF4ControlRequest(request(
      "GET", "B09_F4_CONTROL_V2_TEST_READ_BEARER", F4_CONTROL_TEST_KEY,
      { path: prefix + F4_CONTROL_TEST_KEY },
    ), isolatedDeps);
    assert.equal(test.status, 404);
    assert.equal(isolatedStore.reads, aliasIndex * 2 + 2);
  }

  const readsBeforeCrossMode = isolatedStore.reads;
  assert.equal((await handleF4ControlRequest(request(
    "GET", "B09_F4_CONTROL_V2_TEST_READ_BEARER", F4_CONTROL_KEY,
  ), isolatedDeps)).status, 403);
  assert.equal(isolatedStore.reads, readsBeforeCrossMode);

  for (const path of [
    "/extra/functions/v1/sake-cas-v1/" + F4_CONTROL_KEY,
    "/functions/v1/sake-cas-v1/" + F4_CONTROL_KEY + "/suffix",
    "/functions/v1/sake-cas-v1-extra/" + F4_CONTROL_KEY,
  ]) {
    assert.equal((await handleF4ControlRequest(request(
      "GET", "B09_F4_CONTROL_V2_READ_BEARER", F4_CONTROL_KEY, { path },
    ), isolatedDeps)).status, 404, path);
  }
  assert.equal(isolatedStore.reads, readsBeforeCrossMode);
});

test("duplicate credentials and corrupted journal read fail closed", async () => {
  const duplicate = { ...envValues, B09_F4_CONTROL_V2_WORKER_BEARER: envValues.B09_F4_CONTROL_V2_OWNER_BEARER };
  const duplicateDeps = { env: { get: (name) => duplicate[name] }, store };
  assert.equal((await handleF4ControlRequest(request("GET", "B09_F4_CONTROL_V2_READ_BEARER"), duplicateDeps)).status, 401);
  const value = store.values.get(F4_CONTROL_KEY);
  store.values.set(F4_CONTROL_KEY, { ...value, body: value.body.replace("f4-fixture", "tampered") });
  assert.equal((await handleF4ControlRequest(request("GET", "B09_F4_CONTROL_V2_READ_BEARER"), deps)).status, 503);
});

test("F4 control rejects legacy Bearer-only requests before DB access", async () => {
  store.reads = 0;
  const legacyRequest = new Request(`https://fixture.invalid/functions/v1/sake-cas-v1/${F4_CONTROL_KEY}`, {
    method: "GET", headers: { authorization: "Bearer retired-permit-test-fixture" },
  });
  assert.equal((await handleF4ControlRequest(legacyRequest, deps)).status, 401);
  const oldBearerWithNewHeader = new Request(`https://fixture.invalid/functions/v1/sake-cas-v1/${F4_CONTROL_KEY}`, {
    method: "GET", headers: { authorization: "Bearer retired-permit-test-fixture", "x-b09-cas-auth-generation": "v2" },
  });
  assert.equal((await handleF4ControlRequest(oldBearerWithNewHeader, deps)).status, 401);
  const wrongGeneration = request("GET", "B09_F4_CONTROL_V2_READ_BEARER");
  wrongGeneration.headers.set("x-b09-cas-auth-generation", "v1");
  assert.equal((await handleF4ControlRequest(wrongGeneration, deps)).status, 401);
  const configuredGeneration = envValues.B09_CAS_AUTH_GENERATION;
  envValues.B09_CAS_AUTH_GENERATION = "v1";
  assert.equal((await handleF4ControlRequest(request("GET", "B09_F4_CONTROL_V2_READ_BEARER"), deps)).status, 503);
  envValues.B09_CAS_AUTH_GENERATION = configuredGeneration;
  assert.equal(store.reads, 0);
});

test("Permit and F4 credentials cannot be reused across handler roles", async () => {
  store.reads = 0;
  const permitBearer = envValues.B09_CAS_V2_ISSUER_BEARER;
  const response = await handleF4ControlRequest(new Request(
    `https://fixture.invalid/functions/v1/sake-cas-v1/${F4_CONTROL_KEY}`,
    { method: "GET", headers: { authorization: `Bearer ${permitBearer}`, "x-b09-cas-auth-generation": "v2" } },
  ), deps);
  assert.equal(response.status, 401);
  assert.equal(store.reads, 0);

  const reused = { ...envValues, B09_F4_CONTROL_V2_WORKER_BEARER: permitBearer };
  const reusedDeps = { env: { get: (name) => reused[name] }, store };
  assert.equal((await handleF4ControlRequest(request("GET", "B09_F4_CONTROL_V2_READ_BEARER"), reusedDeps)).status, 401);
  assert.equal(store.reads, 0);
});

test("direct HTTP rejects forged Owner signatures even when the journal hash chain is recomputed", async () => {
  const isolatedStore = new Store();
  const isolatedDeps = { env: { get: (name) => envValues[name] }, store: isolatedStore };
  const forged = await initialDocument();
  forged.events[0].payload.revocation_status.approvals.owner_a.signature = b64(new Uint8Array(64));
  const rehashed = await rehashDocument(forged);
  const result = await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_OWNER_BEARER", F4_CONTROL_KEY, {
    headers: { "content-type": "application/json", "if-none-match": "*" }, body: JSON.stringify(rehashed),
  }), isolatedDeps);
  assert.equal(result.status, 409);
  assert.equal(isolatedStore.values.has(F4_CONTROL_KEY), false);
});

test("direct HTTP rejects a forged independent Auditor signature before Cycle 2 can claim", async () => {
  const isolatedStore = new Store();
  const isolatedDeps = { env: { get: (name) => envValues[name] }, store: isolatedStore };
  const created = await initialDocument();
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_OWNER_BEARER", F4_CONTROL_KEY, {
    headers: { "content-type": "application/json", "if-none-match": "*" }, body: JSON.stringify(created),
  }), isolatedDeps)).status, 204);
  const claim = await append(created, { event: "CYCLE_CLAIMED", cycle_number: 1, run_id: "run-1", go_sha256: created.go_sha256, revocation_sequence: 1, revocation_digest: "c".repeat(64), claimed_at: new Date().toISOString(), source_commit_sha: "d".repeat(40) });
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_WORKER_BEARER", F4_CONTROL_KEY, {
    headers: { "content-type": "application/json", "if-match": '"1"' }, body: JSON.stringify(claim),
  }), isolatedDeps)).status, 204);
  const envelope = await sign("auditor", auditPayload(created));
  envelope.signature = b64(new Uint8Array(64));
  const audit = await append(claim, { event: "CYCLE1_AUDITOR_PASS", artifact_envelope_sha256: await hash(envelope), artifact_id: 17, artifact_archive_digest: "sha256:" + "1".repeat(64), workflow_run_id: "12345", run_attempt: 1, worker_run_id: "run-1", auditor_run_id: "auditor-1", source_commit_sha: "d".repeat(40), auditor_envelope: envelope });
  const result = await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_V2_AUDITOR_BEARER", F4_CONTROL_KEY, {
    headers: { "content-type": "application/json", "if-match": '"2"' }, body: JSON.stringify(audit),
  }), isolatedDeps);
  assert.equal(result.status, 409);
  assert.equal(isolatedStore.values.get(F4_CONTROL_KEY).revision, 2);
});

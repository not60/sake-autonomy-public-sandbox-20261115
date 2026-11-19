import assert from "node:assert/strict";
import test from "node:test";
import { F4_CONTROL_KEY, F4_CONTROL_TEST_KEY, handleF4ControlRequest } from "../supabase/functions/sake-cas-v1/cycle_control.ts";

const names = [
  "B09_F4_CONTROL_OWNER_BEARER", "B09_F4_CONTROL_WORKER_BEARER", "B09_F4_CONTROL_AUDITOR_BEARER", "B09_F4_CONTROL_READ_BEARER",
  "B09_F4_TEST_CONTROL_OWNER_BEARER", "B09_F4_TEST_CONTROL_WORKER_BEARER", "B09_F4_TEST_CONTROL_AUDITOR_BEARER", "B09_F4_TEST_CONTROL_READ_BEARER",
];
const envValues = Object.fromEntries(names.map((name, i) => [name, `fixture-f4-control-role-${i}-long-unique-token` ]));
class Store {
  values = new Map();
  async read(key) { return this.values.get(key); }
  async insertIfAbsent(key, body) { if (this.values.has(key)) return undefined; this.values.set(key, { revision: 1, body }); return 1; }
  async updateIfRevision(key, revision, body) { const current = this.values.get(key); if (!current || current.revision !== revision) return undefined; this.values.set(key, { revision: revision + 1, body }); return revision + 1; }
}
const store = new Store();
const deps = { env: { get: (name) => envValues[name] }, store };
const token = (name) => envValues[name];
const auth = (name) => ({ authorization: `Bearer ${token(name)}` });
const canonical = (value) => value === null || typeof value !== "object"
  ? JSON.stringify(value)
  : Array.isArray(value) ? `[${value.map(canonical).join(",")}]`
  : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
const hash = async (value) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(value)))), (b) => b.toString(16).padStart(2, "0")).join("");
function request(method, name, key = F4_CONTROL_KEY, options = {}) {
  return new Request(`https://fixture.invalid/functions/v1/sake-cas-v1/${key}`, { method, headers: { ...auth(name), ...(options.headers ?? {}) }, body: options.body });
}
async function initialDocument() {
  const statusPayload = { schema: 1, kind: "F4_REVOCATION_STATUS", repository_id: 1458303357, approval_id: "f4-fixture", go_sha256: "a".repeat(64), sequence: 1, status: "ACTIVE", valid_from: "2026-11-19T00:00:00Z", valid_until: "2026-11-19T01:00:00Z" };
  const status = { payload: statusPayload, approvals: {
    owner_a: { key_id: "owner-a-fixture", signature: "x".repeat(86) + "==", payload: statusPayload },
    owner_b: { key_id: "owner-b-fixture", signature: "y".repeat(86) + "==", payload: statusPayload },
  } };
  const eventBody = { sequence: 1, previous_sha256: "0".repeat(64), payload: { event: "CONTROL_CREATED", revocation_status: status } };
  const digest = await hash(eventBody);
  return { schema: 1, repository_id: 1458303357, approval_id: "f4-fixture", go_sha256: "a".repeat(64), base_sha: "b".repeat(40), go_revocation_sequence: 1, revocation_sequence: 1, sequence: 1, head_sha256: digest, events: [{ ...eventBody, event_sha256: digest }] };
}
async function append(document, payload) {
  const body = { sequence: document.sequence + 1, previous_sha256: document.head_sha256, payload };
  const digest = await hash(body);
  const events = [...document.events, { ...body, event_sha256: digest }];
  return { ...document, sequence: events.length, head_sha256: digest, events };
}

test("fixed control keys, independent credentials, and role transitions fail closed", async () => {
  assert.equal(F4_CONTROL_KEY, "repositories/1458303357/b09-f4-cycle-control-v1.json");
  assert.equal(F4_CONTROL_TEST_KEY, "repositories/1458303357/b09-f4-cycle-control-test-v1.json");
  assert.equal((await handleF4ControlRequest(request("GET", "B09_F4_CONTROL_READ_BEARER", "repositories/1458303357/other.json"), deps)).status, 404);
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_OWNER_BEARER", F4_CONTROL_TEST_KEY, { headers: { "content-type": "application/json", "if-none-match": "*" }, body: JSON.stringify(await initialDocument()) }), deps)).status, 403);
  const created = await initialDocument();
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_OWNER_BEARER", F4_CONTROL_KEY, { headers: { "content-type": "application/json", "if-none-match": "*" }, body: JSON.stringify(created) }), deps)).status, 204);
  const claim = await append(created, { event: "CYCLE_CLAIMED", cycle_number: 1, run_id: "run-1", go_sha256: created.go_sha256, revocation_sequence: 1, revocation_digest: "c".repeat(64), claimed_at: "2026-11-19T00:00:00Z", source_commit_sha: "d".repeat(40) });
  const headers = { "content-type": "application/json", "if-match": '"1"' };
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_AUDITOR_BEARER", F4_CONTROL_KEY, { headers, body: JSON.stringify(claim) }), deps)).status, 403);
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_WORKER_BEARER", F4_CONTROL_KEY, { headers, body: JSON.stringify(claim) }), deps)).status, 204);
  const cycle2 = await append(claim, { event: "CYCLE_CLAIMED", cycle_number: 2, run_id: "run-2", go_sha256: created.go_sha256, revocation_sequence: 1, revocation_digest: "c".repeat(64), claimed_at: "2026-11-19T00:00:00Z", source_commit_sha: "e".repeat(40) });
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_WORKER_BEARER", F4_CONTROL_KEY, { headers: { "content-type": "application/json", "if-match": '"2"' }, body: JSON.stringify(cycle2) }), deps)).status, 409);
  const audit = await append(claim, { event: "CYCLE1_AUDITOR_PASS", artifact_envelope_sha256: "f".repeat(64), artifact_id: 17, artifact_archive_digest: "sha256:" + "1".repeat(64), workflow_run_id: "12345", run_attempt: 1, worker_run_id: "run-1", auditor_run_id: "auditor-1", source_commit_sha: "d".repeat(40) });
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_AUDITOR_BEARER", F4_CONTROL_KEY, { headers: { "content-type": "application/json", "if-match": '"2"' }, body: JSON.stringify(audit) }), deps)).status, 204);
  const cycle2AfterAudit = await append(audit, cycle2.events[2].payload);
  assert.equal((await handleF4ControlRequest(request("PUT", "B09_F4_CONTROL_WORKER_BEARER", F4_CONTROL_KEY, { headers: { "content-type": "application/json", "if-match": '"3"' }, body: JSON.stringify(cycle2AfterAudit) }), deps)).status, 204);
  const wrongMode = await handleF4ControlRequest(request("GET", "B09_F4_TEST_CONTROL_READ_BEARER", F4_CONTROL_KEY), deps);
  assert.equal(wrongMode.status, 403);
});

test("duplicate credentials and corrupted journal read fail closed", async () => {
  const duplicate = { ...envValues, B09_F4_CONTROL_WORKER_BEARER: envValues.B09_F4_CONTROL_OWNER_BEARER };
  const duplicateDeps = { env: { get: (name) => duplicate[name] }, store };
  assert.equal((await handleF4ControlRequest(request("GET", "B09_F4_CONTROL_READ_BEARER"), duplicateDeps)).status, 401);
  const value = store.values.get(F4_CONTROL_KEY);
  store.values.set(F4_CONTROL_KEY, { ...value, body: value.body.replace("f4-fixture", "tampered") });
  assert.equal((await handleF4ControlRequest(request("GET", "B09_F4_CONTROL_READ_BEARER"), deps)).status, 503);
});

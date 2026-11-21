import { Client } from "jsr:@db/postgres@0.19.5";
import {
  DELEGATION_TEST_KEY,
  F4_TOKEN_ENV,
  PERMIT_TOKEN_ENV,
  dispatchFixedCasRequest,
  type CasStore,
  type CasStoredDocument,
} from "../supabase/functions/sake-cas-v1/core.ts";
import { canonical, sha256 } from "../supabase/functions/sake-cas-v1/cycle_control.ts";
import { handleDelegationRequest } from "../supabase/functions/sake-cas-v1/delegation_status.ts";

const databaseUrl = Deno.env.get("B09_TEST_DATABASE_URL");
if (!databaseUrl || !databaseUrl.startsWith("postgres://sake_b09_cas_edge@127.0.0.1:")) {
  throw new Error("isolated_loopback_database_required");
}

class PostgresCasStore implements CasStore {
  reads = 0;
  writes = 0;
  async read(key: string): Promise<CasStoredDocument | undefined> {
    if (key !== DELEGATION_TEST_KEY) throw new Error("test_key_scope");
    this.reads++;
    return await this.withClient(async (client) => {
      const result = await client.queryObject<{ revision: number; document_body: string }>(
        "SELECT revision, document_body FROM sake_cas_private.documents WHERE cas_key = $1",
        [key],
      );
      const row = result.rows[0];
      return row ? { revision: Number(row.revision), body: row.document_body } : undefined;
    });
  }
  async insertIfAbsent(key: string, body: string): Promise<number | undefined> {
    if (key !== DELEGATION_TEST_KEY) throw new Error("test_key_scope");
    this.writes++;
    return await this.withClient(async (client) => {
      const result = await client.queryObject<{ revision: number | null }>(
        "SELECT sake_cas_private.insert_if_absent($1, $2) AS revision",
        [key, body],
      );
      const value = result.rows[0]?.revision;
      return value === null || value === undefined ? undefined : Number(value);
    });
  }
  async updateIfRevision(key: string, revision: number, body: string): Promise<number | undefined> {
    if (key !== DELEGATION_TEST_KEY) throw new Error("test_key_scope");
    this.writes++;
    return await this.withClient(async (client) => {
      const result = await client.queryObject<{ revision: number | null }>(
        "SELECT sake_cas_private.update_if_revision($1, $2, $3) AS revision",
        [key, revision, body],
      );
      const value = result.rows[0]?.revision;
      return value === null || value === undefined ? undefined : Number(value);
    });
  }
  private async withClient<T>(operation: (client: Client) => Promise<T>): Promise<T> {
    const client = new Client(databaseUrl!);
    await client.connect();
    try { return await operation(client); }
    finally { await client.end(); }
  }
}

const encoder = new TextEncoder();
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const roles = ["owner_a", "owner_b", "permit_authority", "witness"] as const;
const signingKeys = Object.fromEntries(await Promise.all(roles.map(async (role) => [
  role,
  await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]),
]))) as Record<typeof roles[number], CryptoKeyPair>;
const ownerRegistry = {
  keys: await Promise.all(roles.map(async (role) => ({
    key_id: `${role}-isolated`,
    role,
    public_key: b64(new Uint8Array(await crypto.subtle.exportKey("raw", signingKeys[role].publicKey))),
  }))),
};
const tokenValues = Object.fromEntries(Object.entries(F4_TOKEN_ENV).map(([role, name]) => [
  name,
  `isolated-postgres-integration-bearer-${role}-not-a-secret-2026`,
]));
for (const [role, name] of Object.entries(PERMIT_TOKEN_ENV)) {
  tokenValues[name] = `isolated-postgres-integration-permit-${role}-not-a-secret-2026`;
}
const envValues: Record<string, string> = {
  ...tokenValues,
  B09_CAS_AUTH_GENERATION: "v2",
  B09_F4_TRUSTED_KEYS_JSON: JSON.stringify(ownerRegistry),
};
const env = { get: (name: string) => envValues[name] };
const store = new PostgresCasStore();
const deps = { env, store };

async function signedDocument(status: "ACTIVE" | "REVOKED", sequence: number) {
  const payload = {
    schema: 1,
    kind: "DELEGATION_REVOCATION_STATUS",
    delegation_id: "postgres-integration-test",
    contract_sha256: "b".repeat(64),
    repository_id: 1458303357,
    execution_revision: "a".repeat(40),
    environment: "test",
    sequence,
    status,
    issued_at: new Date(Date.now() - 10_000).toISOString(),
    expires_at: new Date(Date.now() + 120_000).toISOString(),
  };
  const approvals: Record<string, { key_id: string; signature: string }> = {};
  const approvers = status === "ACTIVE" ? ["owner_a", "owner_b"] as const : ["owner_a"] as const;
  for (const role of approvers) {
    approvals[role] = {
      key_id: `${role}-isolated`,
      signature: b64(new Uint8Array(await crypto.subtle.sign("Ed25519", signingKeys[role].privateKey, encoder.encode(canonical(payload))))),
    };
  }
  const statusEnvelope = { payload, approvals };
  return {
    schema: 1,
    environment: "test",
    status: statusEnvelope,
    head_sha256: await sha256(canonical(statusEnvelope)),
  };
}

function request(method: string, role: "testOwner" | "testRead" | "testWorker", body?: unknown, headers: Record<string, string> = {}) {
  return new Request(`http://127.0.0.1/sake-cas-v1/${DELEGATION_TEST_KEY}`, {
    method,
    headers: {
      authorization: `Bearer ${tokenValues[F4_TOKEN_ENV[role]]}`,
      "x-b09-cas-auth-generation": "v2",
      "content-type": "application/json",
      ...headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

Deno.test("real Deno handler to PostgreSQL: CAS, Ed25519, RLS and TEST isolation", async () => {
  const before = await dispatchFixedCasRequest(`/sake-cas-v1/${DELEGATION_TEST_KEY}`, {
    permit: () => "wrong-handler",
    f4Control: () => "wrong-handler",
    delegation: () => "delegation-handler",
  });
  if (before !== "delegation-handler") throw new Error("fixed_dispatch_failed");

  const missing = await handleDelegationRequest(request("GET", "testRead"), deps);
  if (missing.status !== 404) throw new Error(`initial_read_${missing.status}`);

  const active = await signedDocument("ACTIVE", 1);
  const created = await handleDelegationRequest(request("PUT", "testOwner", active, { "if-none-match": "*" }), deps);
  if (created.status !== 204 || created.headers.get("etag") !== '"1"') throw new Error(`initial_cas_${created.status}`);

  const read = await handleDelegationRequest(request("GET", "testRead"), deps);
  if (read.status !== 200 || read.headers.get("etag") !== '"1"') throw new Error(`readback_${read.status}`);
  const readBody = await read.text();
  if (readBody !== JSON.stringify(active)) throw new Error("readback_bytes_mismatch");

  const stale = await handleDelegationRequest(request("PUT", "testOwner", await signedDocument("REVOKED", 2), { "if-match": '"0"' }), deps);
  if (stale.status !== 412) throw new Error(`stale_revision_${stale.status}`);

  const [revokedLeft, revokedRight] = await Promise.all([
    signedDocument("REVOKED", 2),
    signedDocument("REVOKED", 2),
  ]);
  const outcomes = await Promise.all([
    handleDelegationRequest(request("PUT", "testOwner", revokedLeft, { "if-match": '"1"' }), deps),
    handleDelegationRequest(request("PUT", "testOwner", revokedRight, { "if-match": '"1"' }), deps),
  ]);
  const statuses = outcomes.map((response) => response.status).sort();
  if (statuses.filter((status) => status === 204).length !== 1
      || statuses.some((status) => ![204, 409, 412].includes(status))) {
    throw new Error(`concurrent_cas_${statuses.join(",")}`);
  }
  const committed = outcomes.find((response) => response.status === 204)!;
  if (committed.headers.get("etag") !== '"2"') throw new Error("concurrent_cas_etag_mismatch");

  const reactivation = await handleDelegationRequest(request("PUT", "testOwner", await signedDocument("ACTIVE", 3), { "if-match": '"2"' }), deps);
  if (reactivation.status !== 409) throw new Error(`reactivation_${reactivation.status}`);

  const beforeDenied = [store.reads, store.writes];
  const deniedWriter = await handleDelegationRequest(request("PUT", "testWorker", await signedDocument("REVOKED", 3), { "if-match": '"2"' }), deps);
  if (deniedWriter.status !== 403 || store.reads !== beforeDenied[0] || store.writes !== beforeDenied[1]) throw new Error("role_denial_reached_db");
  const crossMode = await handleDelegationRequest(new Request(`http://127.0.0.1/sake-cas-v1/${DELEGATION_TEST_KEY}`, {
    method: "GET",
    headers: { authorization: `Bearer ${tokenValues[F4_TOKEN_ENV.read]}`, "x-b09-cas-auth-generation": "v2" },
  }), deps);
  if (crossMode.status !== 403) throw new Error(`formal_test_crossing_${crossMode.status}`);
  if (store.reads !== beforeDenied[0] || store.writes !== beforeDenied[1]) throw new Error("cross_mode_reached_db");
});

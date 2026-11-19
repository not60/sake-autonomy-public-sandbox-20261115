import { Client } from "jsr:@db/postgres@0.19.5";
import {
  handleCasRequest,
  CAS_KEY,
  type CasStore,
  type CasStoredDocument,
} from "./core.ts";
import { F4_CONTROL_KEY, F4_CONTROL_TEST_KEY, handleF4ControlRequest } from "./cycle_control.ts";

const F4_CONTROL_KEYS = new Set([F4_CONTROL_KEY, F4_CONTROL_TEST_KEY]);
// Keep the historical Permit TEST row under the table CHECK only. The Edge role
// and RPC paths intentionally cannot address it after the V2 retirement cutover.
const CAS_KEYS = new Set([CAS_KEY, ...F4_CONTROL_KEYS]);

class PostgresCasStore implements CasStore {
  constructor(private readonly connectionString: string) {}

  async read(key: string): Promise<CasStoredDocument | undefined> {
    this.assertKey(key);
    return await this.withClient(async (client) => {
      const result = await client.queryObject<{ revision: number; document_body: string }>(
        "SELECT revision, document_body FROM sake_cas_private.documents WHERE cas_key = $1",
        [key],
      );
      const row = result.rows[0];
      if (!row) return undefined;
      return { revision: Number(row.revision), body: row.document_body };
    });
  }

  async insertIfAbsent(key: string, body: string): Promise<number | undefined> {
    this.assertKey(key);
    return await this.withClient(async (client) => {
      const result = await client.queryObject<{ revision: number | null }>(
        "SELECT sake_cas_private.insert_if_absent($1, $2) AS revision",
        [key, body],
      );
      const value = result.rows[0]?.revision;
      return value === null || value === undefined ? undefined : Number(value);
    });
  }

  async updateIfRevision(
    key: string,
    revision: number,
    body: string,
  ): Promise<number | undefined> {
    this.assertKey(key);
    return await this.withClient(async (client) => {
      const result = await client.queryObject<{ revision: number | null }>(
        "SELECT sake_cas_private.update_if_revision($1, $2, $3) AS revision",
        [key, revision, body],
      );
      const value = result.rows[0]?.revision;
      return value === null || value === undefined ? undefined : Number(value);
    });
  }

  private assertKey(key: string): void {
    if (!CAS_KEYS.has(key)) throw new Error("cas_scope_invalid");
  }

  private async withClient<T>(operation: (client: Client) => Promise<T>): Promise<T> {
    const client = new Client(this.connectionString);
    await client.connect();
    try {
      return await operation(client);
    } finally {
      await client.end();
    }
  }
}

const env = { get: (name: string) => Deno.env.get(name) };
const databaseUrl = Deno.env.get("B09_CAS_DB_URL") ?? "";
const store = databaseUrl ? new PostgresCasStore(databaseUrl) : null;

Deno.serve((request) => {
  const path = new URL(request.url).pathname;
  const isF4ControlPath = [...F4_CONTROL_KEYS].some((key) =>
    path === "/functions/v1/sake-cas-v1/" + key || path === "/" + key
  );
  return isF4ControlPath
    ? handleF4ControlRequest(request, { env, store })
    : handleCasRequest(request, { env, store });
});

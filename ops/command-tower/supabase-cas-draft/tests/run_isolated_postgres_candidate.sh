#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../../.." && pwd)"
migration="$repo_root/ops/command-tower/supabase-cas-draft/migrations/20261119000100_f4_cycle_control.sql"
delegation_schema="$repo_root/ops/command-tower/supabase-cas-draft/delegation-status-schema.draft.sql"
test_key="repositories/1458303357/b09-delegation-status-test-v1.json"
permit_test_key="repositories/1458303357/b09-permit-journal-test-v1.json"
admin_user="${PGADMINUSER:-supabase_admin}"
fixture_body='{"fixture":"pre-existing-test-journal","sequence":2,"events":["event-1","event-2"]}'
expected_fixture_sha="f2f01a5a6b234a89cc3e4eb5073a8a243f5d8c3ba3d30eb3e3fd702a6c952ebc"
tmp_dir="$(mktemp -d)"

psql_cmd() {
  psql -X -v ON_ERROR_STOP=1 "$@"
}

cleanup() {
  status=$?
  PGUSER="$admin_user" psql_cmd -c "DELETE FROM sake_cas_private.documents WHERE cas_key = '$test_key';" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
  exit "$status"
}
trap cleanup EXIT

ready=0
for attempt in $(seq 1 45); do
  if pg_isready -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" -U "${PGUSER:-postgres}" -d "${PGDATABASE:-postgres}" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo "HOLD:isolated_postgres_unavailable" >&2; exit 1; }
[[ "$admin_user" == "supabase_admin" ]] || { echo "HOLD:managed_admin_bootstrap_role_required" >&2; exit 1; }

PGUSER="$admin_user" psql_cmd <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'postgres') THEN EXECUTE 'CREATE ROLE postgres LOGIN CREATEROLE NOINHERIT NOBYPASSRLS'; END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'anon') THEN EXECUTE 'CREATE ROLE anon NOLOGIN'; END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'authenticated') THEN EXECUTE 'CREATE ROLE authenticated NOLOGIN'; END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'service_role') THEN EXECUTE 'CREATE ROLE service_role NOLOGIN BYPASSRLS'; END IF;
END
$$;
SQL
PGUSER="$admin_user" psql_cmd -c "ALTER DATABASE ${PGDATABASE:-postgres} OWNER TO postgres;"

PGUSER=postgres psql_cmd -f "$repo_root/ops/command-tower/supabase-cas-draft/schema.sql"
PGUSER="$admin_user" psql_cmd -c "INSERT INTO sake_cas_private.documents(cas_key, revision, document_body) VALUES ('$permit_test_key', 2, '$fixture_body') ON CONFLICT (cas_key) DO NOTHING;"

stored_fixture="$(PGUSER="$admin_user" psql_cmd -Atq -c "SELECT document_body FROM sake_cas_private.documents WHERE cas_key = '$permit_test_key' AND revision = 2;")"
[[ "$(printf '%s' "$stored_fixture" | shasum -a 256 | awk '{print $1}')" == "$expected_fixture_sha" ]] \
  || { echo "HOLD:historical_test_journal_fixture_mismatch" >&2; exit 1; }

PGUSER="$admin_user" psql_cmd -c "GRANT sake_b09_cas_edge TO postgres WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;"
PGUSER=postgres psql_cmd -f "$migration"
PGUSER=postgres psql_cmd -f "$delegation_schema"

PGUSER="$admin_user" psql_cmd <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (
    SELECT FROM pg_catalog.pg_constraint
    WHERE conrelid = 'sake_cas_private.documents'::regclass
      AND conname = 'documents_fixed_public_repo_key'
      AND pg_catalog.pg_get_constraintdef(oid) LIKE '%b09-permit-journal-test-v1.json%'
  ) THEN RAISE EXCEPTION 'historical_test_key_not_retained_by_check'; END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_class WHERE oid = 'sake_cas_private.documents'::regclass AND relrowsecurity AND relforcerowsecurity)
    THEN RAISE EXCEPTION 'forced_rls_missing'; END IF;
  IF EXISTS (
    SELECT FROM pg_catalog.pg_policy
    WHERE polrelid = 'sake_cas_private.documents'::regclass
      AND polname = 'b09_edge_fixed_key_only'
      AND pg_catalog.pg_get_expr(polqual, polrelid) LIKE '%b09-permit-journal-test-v1.json%'
  ) THEN RAISE EXCEPTION 'retired_test_key_in_edge_policy'; END IF;
  IF EXISTS (
    SELECT FROM pg_catalog.pg_proc
    WHERE oid IN ('sake_cas_private.insert_if_absent(text,text)'::regprocedure,
                  'sake_cas_private.update_if_revision(text,bigint,text)'::regprocedure)
      AND prosecdef
  ) THEN RAISE EXCEPTION 'cas_rpc_not_security_invoker'; END IF;
END
\$\$;
SQL
PGUSER=sake_b09_cas_edge psql_cmd <<SQL
DO \$\$
BEGIN
  IF (SELECT count(*) FROM sake_cas_private.documents WHERE cas_key = '$permit_test_key') <> 0
    THEN RAISE EXCEPTION 'retired_permit_test_row_visible'; END IF;
  BEGIN
    PERFORM sake_cas_private.insert_if_absent('$permit_test_key', '{}');
    RAISE EXCEPTION 'retired_permit_test_write_was_accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL;
  END;
END
\$\$;
SQL

export B09_TEST_DATABASE_URL="postgres://sake_b09_cas_edge@${PGHOST:-127.0.0.1}:${PGPORT:-5432}/${PGDATABASE:-postgres}"
deno test --allow-net="${PGHOST:-127.0.0.1}:${PGPORT:-5432}" --allow-env=B09_TEST_DATABASE_URL \
  "$repo_root/ops/command-tower/supabase-cas-draft/tests/delegation_status_postgres_integration.ts"

PGUSER="$admin_user" psql_cmd -c "DELETE FROM sake_cas_private.documents WHERE cas_key = '$test_key';"
remaining_test_rows="$(PGUSER="$admin_user" psql_cmd -Atq -c "SELECT count(*) FROM sake_cas_private.documents WHERE cas_key LIKE 'repositories/1458303357/b09-%';")"
[[ "$remaining_test_rows" == 1 ]] || { echo "HOLD:unexpected_test_cas_rows_remain" >&2; exit 1; }
stored_fixture="$(PGUSER="$admin_user" psql_cmd -Atq -c "SELECT document_body FROM sake_cas_private.documents WHERE cas_key = '$permit_test_key' AND revision = 2;")"
[[ "$(printf '%s' "$stored_fixture" | shasum -a 256 | awk '{print $1}')" == "$expected_fixture_sha" ]] \
  || { echo "HOLD:historical_test_journal_changed" >&2; exit 1; }
echo "PASS:full_f4_migration_delegation_ddl_rls_cas_ed25519_readback_cleanup"

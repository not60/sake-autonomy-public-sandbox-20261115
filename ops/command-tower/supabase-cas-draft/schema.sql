-- LOCAL DRAFT ONLY. Do not apply without a separate exact-SHA Owner approval.
-- This candidate is scoped to GitHub repo 1458303357 and two fixed, separate journal keys.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'sake_b09_cas_edge'
      AND (rolsuper OR rolinherit OR rolbypassrls OR rolcreatedb
        OR rolcreaterole OR rolreplication OR NOT rolcanlogin)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    WHERE m.member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'sake_b09_cas_edge')
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members m
    WHERE m.roleid = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'sake_b09_cas_edge')
  ) THEN
    RAISE EXCEPTION 'existing sake_b09_cas_edge role has unsafe attributes';
  ELSIF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'sake_b09_cas_edge'
  ) THEN
    EXECUTE 'CREATE ROLE sake_b09_cas_edge LOGIN NOINHERIT NOBYPASSRLS';
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS sake_cas_private AUTHORIZATION postgres;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_namespace n
    JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
    WHERE n.nspname = 'sake_cas_private' AND r.rolname = 'postgres'
  ) THEN
    RAISE EXCEPTION 'existing sake_cas_private schema owner is unexpected';
  END IF;
END
$$;
GRANT CONNECT ON DATABASE postgres TO sake_b09_cas_edge;
REVOKE ALL ON SCHEMA sake_cas_private FROM PUBLIC, anon, authenticated, service_role;
GRANT USAGE ON SCHEMA sake_cas_private TO sake_b09_cas_edge;

CREATE TABLE IF NOT EXISTS sake_cas_private.documents (
  cas_key text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision > 0),
  document_body text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT documents_fixed_public_repo_key
    CHECK (cas_key = ANY (ARRAY[
      'repositories/1458303357/b09-permit-journal-v1.json'::text,
      'repositories/1458303357/b09-permit-journal-test-v1.json'::text
    ])),
  CONSTRAINT documents_body_size_limit
    CHECK (octet_length(convert_to(document_body, 'UTF8')) <= 1048576)
);
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'sake_cas_private'
      AND c.relname = 'documents'
      AND c.relkind = 'r'
      AND c.relowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'postgres')
      AND (
        SELECT array_agg(a.attname::text ORDER BY a.attnum)
        FROM pg_catalog.pg_attribute a
        WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
      ) = ARRAY['cas_key', 'revision', 'document_body', 'updated_at']
      AND (
        SELECT array_agg(pg_catalog.format_type(a.atttypid, a.atttypmod) ORDER BY a.attnum)
        FROM pg_catalog.pg_attribute a
        WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
      ) = ARRAY['text', 'bigint', 'text', 'timestamp with time zone']
      AND (
        SELECT count(*)
        FROM pg_catalog.pg_constraint q
        WHERE q.conrelid = c.oid
      ) = 4
      AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint q
        WHERE q.conrelid = c.oid
          AND q.conname = 'documents_pkey'
          AND q.contype = 'p'
          AND q.conkey = ARRAY[1]::smallint[]
          AND q.convalidated
          AND NOT q.condeferrable
      )
      AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint q
        WHERE q.conrelid = c.oid
          AND q.conname = 'documents_revision_check'
          AND q.contype = 'c'
          AND q.convalidated
          AND pg_catalog.regexp_replace(pg_catalog.pg_get_constraintdef(q.oid), '[[:space:]]+', '', 'g')
              = 'CHECK((revision>0))'
      )
      AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint q
        WHERE q.conrelid = c.oid
          AND q.conname = 'documents_fixed_public_repo_key'
          AND q.contype = 'c'
          AND q.convalidated
          AND pg_catalog.regexp_replace(pg_catalog.pg_get_constraintdef(q.oid), '[[:space:]]+', '', 'g')
              = pg_catalog.regexp_replace(
                  pg_catalog.format(
                    'CHECK ((cas_key = ANY (ARRAY[%L::text, %L::text])))',
                    'repositories/1458303357/b09-permit-journal-v1.json',
                    'repositories/1458303357/b09-permit-journal-test-v1.json'
                  ),
                  '[[:space:]]+', '', 'g'
                )
      )
      AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint q
        WHERE q.conrelid = c.oid
          AND q.conname = 'documents_body_size_limit'
          AND q.contype = 'c'
          AND q.convalidated
          AND pg_catalog.regexp_replace(pg_catalog.pg_get_constraintdef(q.oid), '[[:space:]]+', '', 'g')
              = 'CHECK((octet_length(convert_to(document_body,''UTF8''::name))<=1048576))'
      )
  ) THEN
    RAISE EXCEPTION 'existing CAS document table has unexpected owner or structure';
  END IF;
END
$$;

ALTER TABLE sake_cas_private.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE sake_cas_private.documents FORCE ROW LEVEL SECURITY;
DO $$
DECLARE
  existing_policy_count integer;
  exact_policy_count integer;
BEGIN
  SELECT count(*) INTO existing_policy_count
  FROM pg_catalog.pg_policies
  WHERE schemaname = 'sake_cas_private' AND tablename = 'documents';
  SELECT count(*) INTO exact_policy_count
  FROM pg_catalog.pg_policies
  WHERE schemaname = 'sake_cas_private'
    AND tablename = 'documents'
    AND policyname = 'b09_edge_fixed_key_only'
    AND permissive = 'PERMISSIVE'
    AND pg_catalog.array_to_string(roles, ',') = 'sake_b09_cas_edge'
    AND cmd = 'ALL'
    AND pg_catalog.regexp_replace(qual, '[[:space:]]+', '', 'g')
        = pg_catalog.regexp_replace(pg_catalog.format(
            '(cas_key = ANY (ARRAY[%L::text, %L::text]))',
            'repositories/1458303357/b09-permit-journal-v1.json',
            'repositories/1458303357/b09-permit-journal-test-v1.json'
          ), '[[:space:]]+', '', 'g')
    AND pg_catalog.regexp_replace(with_check, '[[:space:]]+', '', 'g')
        = pg_catalog.regexp_replace(pg_catalog.format(
            '(cas_key = ANY (ARRAY[%L::text, %L::text]))',
            'repositories/1458303357/b09-permit-journal-v1.json',
            'repositories/1458303357/b09-permit-journal-test-v1.json'
          ), '[[:space:]]+', '', 'g');

  IF existing_policy_count = 0 THEN
    CREATE POLICY b09_edge_fixed_key_only
      ON sake_cas_private.documents
      FOR ALL TO sake_b09_cas_edge
      USING (cas_key = ANY (ARRAY[
        'repositories/1458303357/b09-permit-journal-v1.json'::text,
        'repositories/1458303357/b09-permit-journal-test-v1.json'::text
      ]))
      WITH CHECK (cas_key = ANY (ARRAY[
        'repositories/1458303357/b09-permit-journal-v1.json'::text,
        'repositories/1458303357/b09-permit-journal-test-v1.json'::text
      ]));
  ELSIF existing_policy_count <> 1 OR exact_policy_count <> 1 THEN
    RAISE EXCEPTION 'existing CAS RLS policies differ from the fixed-key policy';
  END IF;
END
$$;

REVOKE ALL ON TABLE sake_cas_private.documents
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE sake_cas_private.documents TO sake_b09_cas_edge;

-- Atomic first write. NULL means the key already exists; caller returns 412.
CREATE OR REPLACE FUNCTION sake_cas_private.insert_if_absent(
  p_key text, p_document_body text
) RETURNS bigint
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, sake_cas_private
AS $$
DECLARE
  inserted_revision bigint;
BEGIN
  IF p_key IS NULL OR p_key <> ALL (ARRAY[
       'repositories/1458303357/b09-permit-journal-v1.json'::text,
       'repositories/1458303357/b09-permit-journal-test-v1.json'::text
     ])
     OR p_document_body IS NULL
     OR octet_length(convert_to(p_document_body, 'UTF8')) > 1048576 THEN
    RAISE EXCEPTION 'CAS scope or size rejected' USING ERRCODE = '22023';
  END IF;
  INSERT INTO sake_cas_private.documents(cas_key, revision, document_body)
    VALUES (p_key, 1, p_document_body)
    ON CONFLICT (cas_key) DO NOTHING
    RETURNING revision INTO inserted_revision;
  RETURN inserted_revision;
END
$$;

-- Atomic revision CAS. NULL means the expected revision was stale; caller returns 412.
CREATE OR REPLACE FUNCTION sake_cas_private.update_if_revision(
  p_key text, p_expected_revision bigint, p_document_body text
) RETURNS bigint
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, sake_cas_private
AS $$
DECLARE
  updated_revision bigint;
BEGIN
  IF p_key IS NULL OR p_key <> ALL (ARRAY[
       'repositories/1458303357/b09-permit-journal-v1.json'::text,
       'repositories/1458303357/b09-permit-journal-test-v1.json'::text
     ])
     OR p_document_body IS NULL
     OR p_expected_revision IS NULL
     OR p_expected_revision <= 0
     OR octet_length(convert_to(p_document_body, 'UTF8')) > 1048576 THEN
    RAISE EXCEPTION 'CAS scope, revision, or size rejected' USING ERRCODE = '22023';
  END IF;
  UPDATE sake_cas_private.documents
     SET revision = revision + 1,
         document_body = p_document_body,
         updated_at = clock_timestamp()
   WHERE cas_key = p_key AND revision = p_expected_revision
   RETURNING revision INTO updated_revision;
  RETURN updated_revision;
END
$$;

REVOKE ALL ON FUNCTION sake_cas_private.insert_if_absent(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sake_cas_private.update_if_revision(text, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sake_cas_private.insert_if_absent(text, text) TO sake_b09_cas_edge;
GRANT EXECUTE ON FUNCTION sake_cas_private.update_if_revision(text, bigint, text) TO sake_b09_cas_edge;

-- No DELETE/TRUNCATE grant or public Data API exposure is defined here.

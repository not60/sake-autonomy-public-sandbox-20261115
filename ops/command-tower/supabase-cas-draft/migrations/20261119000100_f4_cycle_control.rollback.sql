-- LOCAL DRAFT ONLY. Use only after an approved F4 deployment rollback decision.
-- It removes F4 keys while retaining the historical Permit TEST row under the
-- table CHECK only. The restored role/RPC boundary continues to allow formal Permit only.
BEGIN;
DO $$
DECLARE
  fixed_key_check_count integer;
  policy_count integer;
  exact_policy_count integer;
BEGIN
  IF EXISTS (SELECT 1 FROM sake_cas_private.documents WHERE cas_key IN (
    'repositories/1458303357/b09-f4-cycle-control-v1.json',
    'repositories/1458303357/b09-f4-cycle-control-test-v1.json'
  )) THEN
    RAISE EXCEPTION 'rollback refused: F4 cycle-control records exist; preserve and investigate';
  END IF;
  SELECT count(*) INTO fixed_key_check_count FROM pg_catalog.pg_constraint q
  WHERE q.conrelid = 'sake_cas_private.documents'::regclass
    AND q.conname = 'documents_fixed_public_repo_key' AND q.contype = 'c' AND q.convalidated
    AND pg_catalog.regexp_replace(pg_catalog.pg_get_constraintdef(q.oid), '[[:space:]]+', '', 'g')
      = pg_catalog.regexp_replace(pg_catalog.format(
        'CHECK ((cas_key = ANY (ARRAY[%L::text, %L::text, %L::text, %L::text])))',
        'repositories/1458303357/b09-permit-journal-v1.json',
        'repositories/1458303357/b09-permit-journal-test-v1.json',
        'repositories/1458303357/b09-f4-cycle-control-v1.json',
        'repositories/1458303357/b09-f4-cycle-control-test-v1.json'
      ), '[[:space:]]+', '', 'g');
  SELECT count(*) INTO policy_count FROM pg_catalog.pg_policies
  WHERE schemaname = 'sake_cas_private' AND tablename = 'documents';
  SELECT count(*) INTO exact_policy_count FROM pg_catalog.pg_policies
  WHERE schemaname = 'sake_cas_private' AND tablename = 'documents'
    AND policyname = 'b09_edge_fixed_key_only' AND permissive = 'PERMISSIVE'
    AND pg_catalog.array_to_string(roles, ',') = 'sake_b09_cas_edge' AND cmd = 'ALL'
    AND pg_catalog.regexp_replace(qual, '[[:space:]]+', '', 'g')
      = pg_catalog.regexp_replace(pg_catalog.format(
        '(cas_key = ANY (ARRAY[%L::text, %L::text, %L::text]))',
        'repositories/1458303357/b09-permit-journal-v1.json',
        'repositories/1458303357/b09-f4-cycle-control-v1.json',
        'repositories/1458303357/b09-f4-cycle-control-test-v1.json'
      ), '[[:space:]]+', '', 'g')
    AND pg_catalog.regexp_replace(with_check, '[[:space:]]+', '', 'g')
      = pg_catalog.regexp_replace(pg_catalog.format(
        '(cas_key = ANY (ARRAY[%L::text, %L::text, %L::text]))',
        'repositories/1458303357/b09-permit-journal-v1.json',
        'repositories/1458303357/b09-f4-cycle-control-v1.json',
        'repositories/1458303357/b09-f4-cycle-control-test-v1.json'
      ), '[[:space:]]+', '', 'g');
  IF fixed_key_check_count <> 1 OR policy_count <> 1 OR exact_policy_count <> 1 THEN
    RAISE EXCEPTION 'rollback refused: schema or RLS policy drift';
  END IF;
END
$$;

DROP POLICY b09_edge_fixed_key_only ON sake_cas_private.documents;
ALTER TABLE sake_cas_private.documents DROP CONSTRAINT documents_fixed_public_repo_key;
ALTER TABLE sake_cas_private.documents ADD CONSTRAINT documents_fixed_public_repo_key CHECK (cas_key = ANY (ARRAY[
  'repositories/1458303357/b09-permit-journal-v1.json'::text,
  'repositories/1458303357/b09-permit-journal-test-v1.json'::text
]));
CREATE POLICY b09_edge_fixed_key_only ON sake_cas_private.documents
  FOR ALL TO sake_b09_cas_edge
  USING (cas_key = ANY (ARRAY[
    'repositories/1458303357/b09-permit-journal-v1.json'::text
  ]))
  WITH CHECK (cas_key = ANY (ARRAY[
    'repositories/1458303357/b09-permit-journal-v1.json'::text
  ]));

CREATE OR REPLACE FUNCTION sake_cas_private.insert_if_absent(p_key text, p_document_body text)
RETURNS bigint LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, sake_cas_private AS $$
DECLARE inserted_revision bigint;
BEGIN
  IF p_key IS NULL OR p_key <> ALL (ARRAY[
    'repositories/1458303357/b09-permit-journal-v1.json'::text
  ]) OR p_document_body IS NULL OR octet_length(convert_to(p_document_body, 'UTF8')) > 1048576 THEN
    RAISE EXCEPTION 'CAS scope or size rejected' USING ERRCODE = '22023';
  END IF;
  INSERT INTO sake_cas_private.documents(cas_key, revision, document_body)
    VALUES (p_key, 1, p_document_body) ON CONFLICT (cas_key) DO NOTHING
    RETURNING revision INTO inserted_revision;
  RETURN inserted_revision;
END
$$;
CREATE OR REPLACE FUNCTION sake_cas_private.update_if_revision(p_key text, p_expected_revision bigint, p_document_body text)
RETURNS bigint LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, sake_cas_private AS $$
DECLARE updated_revision bigint;
BEGIN
  IF p_key IS NULL OR p_key <> ALL (ARRAY[
    'repositories/1458303357/b09-permit-journal-v1.json'::text
  ]) OR p_document_body IS NULL OR p_expected_revision IS NULL OR p_expected_revision <= 0
     OR octet_length(convert_to(p_document_body, 'UTF8')) > 1048576 THEN
    RAISE EXCEPTION 'CAS scope, revision, or size rejected' USING ERRCODE = '22023';
  END IF;
  UPDATE sake_cas_private.documents SET revision = revision + 1,
      document_body = p_document_body, updated_at = clock_timestamp()
   WHERE cas_key = p_key AND revision = p_expected_revision
   RETURNING revision INTO updated_revision;
  RETURN updated_revision;
END
$$;
REVOKE ALL ON FUNCTION sake_cas_private.insert_if_absent(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sake_cas_private.update_if_revision(text, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sake_cas_private.insert_if_absent(text, text) TO sake_b09_cas_edge;
GRANT EXECUTE ON FUNCTION sake_cas_private.update_if_revision(text, bigint, text) TO sake_b09_cas_edge;
COMMIT;

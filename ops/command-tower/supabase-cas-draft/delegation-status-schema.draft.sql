-- DRAFT_HOLD supplemental SQL. Not applied. Review exact SHA before deployment.
-- Existing membership/role preflight remains prerequisite; no role grants added.
BEGIN;
LOCK TABLE sake_cas_private.documents IN ACCESS EXCLUSIVE MODE;
DO $$
DECLARE c text; p text; found_keys text[];
BEGIN
 SELECT pg_get_constraintdef(oid) INTO c FROM pg_constraint
 WHERE conrelid='sake_cas_private.documents'::regclass AND conname='documents_fixed_public_repo_key';
 SELECT pg_get_expr(polqual,polrelid) INTO p FROM pg_policy
 WHERE polrelid='sake_cas_private.documents'::regclass AND polname='b09_edge_fixed_key_only';
 SELECT array_agg(m[1] ORDER BY m[1]) INTO found_keys FROM regexp_matches(c, '''(repositories/[^'']+)''', 'g') AS m;
 IF found_keys IS DISTINCT FROM ARRAY[
 'repositories/1458303357/b09-f4-cycle-control-test-v1.json',
 'repositories/1458303357/b09-f4-cycle-control-v1.json',
 'repositories/1458303357/b09-permit-journal-test-v1.json',
 'repositories/1458303357/b09-permit-journal-v1.json']
 OR (SELECT count(*) FROM pg_policy WHERE polrelid='sake_cas_private.documents'::regclass) <> 1
 OR NOT EXISTS (SELECT FROM pg_policy WHERE polrelid='sake_cas_private.documents'::regclass
 AND polname='b09_edge_fixed_key_only' AND polcmd='*' AND polpermissive
 AND polroles=ARRAY['sake_b09_cas_edge'::regrole::oid]
 AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid))
 THEN RAISE EXCEPTION 'unexpected CAS constraint or policy'; END IF;
 SELECT array_agg(m[1] ORDER BY m[1]) INTO found_keys FROM regexp_matches(p, '''(repositories/[^'']+)''', 'g') AS m;
 IF found_keys IS DISTINCT FROM ARRAY[
 'repositories/1458303357/b09-f4-cycle-control-test-v1.json',
 'repositories/1458303357/b09-f4-cycle-control-v1.json',
 'repositories/1458303357/b09-permit-journal-v1.json']
 THEN RAISE EXCEPTION 'unexpected executable CAS keys'; END IF;
 IF c IS NULL OR p IS NULL OR c LIKE '%delegation-status%' OR p LIKE '%permit-journal-test%'
 OR c NOT LIKE '%b09-permit-journal-test-v1.json%' OR p NOT LIKE '%b09-f4-cycle-control-test-v1.json%'
 OR NOT EXISTS (SELECT FROM pg_class WHERE oid='sake_cas_private.documents'::regclass AND relrowsecurity AND relforcerowsecurity)
 OR EXISTS (SELECT FROM pg_proc WHERE oid IN ('sake_cas_private.insert_if_absent(text,text)'::regprocedure,
 'sake_cas_private.update_if_revision(text,bigint,text)'::regprocedure) AND prosecdef)
 THEN RAISE EXCEPTION 'delegation CAS prerequisite mismatch'; END IF;
END $$;
ALTER TABLE sake_cas_private.documents
  DROP CONSTRAINT documents_fixed_public_repo_key;
ALTER TABLE sake_cas_private.documents
  ADD CONSTRAINT documents_fixed_public_repo_key CHECK (cas_key = ANY (ARRAY[
    'repositories/1458303357/b09-permit-journal-v1.json'::text,
    'repositories/1458303357/b09-permit-journal-test-v1.json'::text,
    'repositories/1458303357/b09-f4-cycle-control-v1.json'::text,
    'repositories/1458303357/b09-f4-cycle-control-test-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-test-v1.json'::text
  ]));

DROP POLICY b09_edge_fixed_key_only ON sake_cas_private.documents;
CREATE POLICY b09_edge_fixed_key_only ON sake_cas_private.documents
  FOR ALL TO sake_b09_cas_edge
  USING (cas_key = ANY (ARRAY[
    'repositories/1458303357/b09-permit-journal-v1.json'::text,
    'repositories/1458303357/b09-f4-cycle-control-v1.json'::text,
    'repositories/1458303357/b09-f4-cycle-control-test-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-test-v1.json'::text
  ]))
  WITH CHECK (cas_key = ANY (ARRAY[
    'repositories/1458303357/b09-permit-journal-v1.json'::text,
    'repositories/1458303357/b09-f4-cycle-control-v1.json'::text,
    'repositories/1458303357/b09-f4-cycle-control-test-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-test-v1.json'::text
  ]));

CREATE OR REPLACE FUNCTION sake_cas_private.insert_if_absent(
  p_key text, p_document_body text
) RETURNS bigint LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, sake_cas_private AS $$
DECLARE inserted_revision bigint;
BEGIN
  IF p_key IS NULL OR p_key <> ALL (ARRAY[
       'repositories/1458303357/b09-permit-journal-v1.json'::text,
       'repositories/1458303357/b09-f4-cycle-control-v1.json'::text,
       'repositories/1458303357/b09-f4-cycle-control-test-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-test-v1.json'::text
     ]) OR p_document_body IS NULL
     OR octet_length(convert_to(p_document_body, 'UTF8')) > 1048576 THEN
    RAISE EXCEPTION 'CAS scope or size rejected' USING ERRCODE = '22023';
  END IF;
  INSERT INTO sake_cas_private.documents(cas_key, revision, document_body)
    VALUES (p_key, 1, p_document_body)
    ON CONFLICT (cas_key) DO NOTHING RETURNING revision INTO inserted_revision;
  RETURN inserted_revision;
END
$$;

CREATE OR REPLACE FUNCTION sake_cas_private.update_if_revision(
  p_key text, p_expected_revision bigint, p_document_body text
) RETURNS bigint LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, sake_cas_private AS $$
DECLARE updated_revision bigint;
BEGIN
  IF p_key IS NULL OR p_key <> ALL (ARRAY[
       'repositories/1458303357/b09-permit-journal-v1.json'::text,
       'repositories/1458303357/b09-f4-cycle-control-v1.json'::text,
       'repositories/1458303357/b09-f4-cycle-control-test-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-v1.json'::text,
    'repositories/1458303357/b09-delegation-status-test-v1.json'::text
     ]) OR p_document_body IS NULL OR p_expected_revision IS NULL
     OR p_expected_revision <= 0
     OR octet_length(convert_to(p_document_body, 'UTF8')) > 1048576 THEN
    RAISE EXCEPTION 'CAS scope, revision, or size rejected' USING ERRCODE = '22023';
  END IF;
  UPDATE sake_cas_private.documents
     SET revision = revision + 1, document_body = p_document_body,
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
COMMIT;

-- Roll back only this allowlist extension after confirming both F4 keys have no rows.
-- Never delete CAS data. If either key has a row, retain schema and investigate instead.

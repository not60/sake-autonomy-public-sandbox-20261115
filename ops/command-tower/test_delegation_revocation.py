"""Isolated adapter tests. Signature primitive stubbed here; Edge tests use real Ed25519."""
import copy
import hashlib
import unittest
from unittest.mock import patch
from datetime import datetime,timezone,timedelta
from attestations import canonical_json
from cas_journal import CasValue
from trusted_key_registry import TrustedVerificationKey
from delegation_revocation import DelegationStatusStore,DelegationStatusHold,verify_status
from f4_signing_provider import build_delegation_status_reader

class Backend:
    def __init__(self): self.values={};self.writes=0;self.fail=False
    def read(self,key): return self.values.get(key)
    def compare_and_swap(self,key,version,body):
        self.writes+=1
        if self.fail: raise RuntimeError('unknown')
        old=self.values.get(key)
        if (old.version if old else None)!=version: raise RuntimeError('conflict')
        value=CasValue(body,str(int(version or '0')+1));self.values[key]=value;return value.version

class DelegationReaderTests(unittest.TestCase):
    def setUp(self):
        self.patch=patch('delegation_revocation._verify_ed25519',return_value=None);self.patch.start();self.addCleanup(self.patch.stop)
        self.keys={r:TrustedVerificationKey(r,r,bytes([i])*32) for i,r in enumerate(('owner_a','owner_b'),1)}
        self.contract={'delegation_id':'fixture','repository_id':1458303357,'execution_revision':'a'*40,'revocation':{'sequence':1}}
        now=datetime.now(timezone.utc)
        self.payload={'schema':1,'kind':'DELEGATION_REVOCATION_STATUS','delegation_id':'fixture','repository_id':1458303357,'execution_revision':'a'*40,'contract_sha256':hashlib.sha256(canonical_json(self.contract)).hexdigest(),'environment':'test','sequence':1,'status':'ACTIVE','issued_at':(now-timedelta(seconds=2)).isoformat().replace('+00:00','Z'),'expires_at':(now+timedelta(minutes=2)).isoformat().replace('+00:00','Z')}
        self.backend=Backend();self.store=DelegationStatusStore(self.backend,trusted_owner_keys=self.keys,environment='test')
    def envelope(self,**changes): return {'payload':dict(self.payload,**changes),'approvals':{r:{'key_id':r,'signature':'YQ=='} for r in self.keys}}
    def test_full_status_to_existing_three_field_provider_reader(self):
        self.store.update(self.envelope())
        read=build_delegation_status_reader(backend=self.backend,trusted_owner_keys=self.keys,environment='test',delegation_payload=self.contract)
        self.assertEqual(read(self.contract),{'delegation_id':'fixture','sequence':1,'status':'ACTIVE'})
        for field,value in [('repository_id',1),('execution_revision','b'*40),('delegation_id','other'),('extra',True)]:
            bad=dict(self.contract,**{field:value})
            with self.assertRaises(DelegationStatusHold): read(bad)
    def test_revoke_terminal_replay_and_mode_rejection(self):
        self.store.update(self.envelope())
        revoked=self.envelope(sequence=2,status='REVOKED'); del revoked['approvals']['owner_b']
        self.store.update(revoked)
        with self.assertRaises(DelegationStatusHold): self.store.update(self.envelope(sequence=3))
        formal=DelegationStatusStore(self.backend,trusted_owner_keys=self.keys,environment='formal')
        self.assertIsNone(formal.read())
        with self.assertRaises(DelegationStatusHold): formal.update(self.envelope())
    def test_expired_bad_signature_and_scope_missing(self):
        for change in ({'expires_at':'2000-01-01T00:00:00Z'},{'repository_id':2},{'execution_revision':'bad'},{'sequence':True}):
            with self.assertRaises(DelegationStatusHold):verify_status(self.envelope(**change),trusted_owner_keys=self.keys)
        with patch('delegation_revocation._verify_ed25519',side_effect=ValueError):
            with self.assertRaises(DelegationStatusHold): self.store.update(self.envelope())
        self.assertEqual(self.backend.writes,0)
    def test_unknown_cas_result_has_no_retry(self):
        self.backend.fail=True
        with self.assertRaises(DelegationStatusHold):self.store.update(self.envelope())
        self.assertEqual(self.backend.writes,1)

if __name__=='__main__': unittest.main()

/** DRAFT_HOLD. Existing F4 Owner/read credentials; no Permit credential reuse. */
import { casAuthGenerationFailure, resolveFixedCasRoute, DELEGATION_KEY, type CasDependencies } from './core.ts';
import { identify, loadOwnerKeys, canonical, sha256, ownedCryptoBuffer } from './cycle_control.ts';
const reply = (status: number) => new Response(null, {status, headers: {'cache-control':'no-store'}});
const exact = (v: any, fields: string[]) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === fields.sort().join(',');
export async function validateDelegationDocument(body: string, mode: string, env: CasDependencies['env'], fresh = true): Promise<any> {
  const d = JSON.parse(body), e = d.status, p = e?.payload;
  if (!exact(d, ['schema','environment','status','head_sha256']) || d.schema !== 1 || d.environment !== mode
      || !exact(e,['payload','approvals']) || !exact(p,['schema','kind','delegation_id','contract_sha256','repository_id','execution_revision','environment','sequence','status','issued_at','expires_at'])
      || p.schema !== 1 || p.kind !== 'DELEGATION_REVOCATION_STATUS' || p.repository_id !== 1458303357 || p.environment !== mode
      || typeof p.delegation_id !== 'string' || !p.delegation_id || !/^[a-f0-9]{64}$/.test(p.contract_sha256)
      || !/^[a-f0-9]{40}$/.test(p.execution_revision) || !Number.isSafeInteger(p.sequence) || p.sequence < 1
      || !['ACTIVE','REVOKED'].includes(p.status) || !e.approvals || !Object.keys(e.approvals).length
      || Object.keys(e.approvals).some(r=>!['owner_a','owner_b'].includes(r))
      || (p.status === 'ACTIVE' && !exact(e.approvals,['owner_a','owner_b']))) throw Error('status_scope');
  const start = Date.parse(p.issued_at), end = Date.parse(p.expires_at);
  if (!p.issued_at.endsWith('Z') || !p.expires_at.endsWith('Z') || !Number.isFinite(start) || !Number.isFinite(end) || end <= start
      || (fresh && (Date.now() < start || Date.now() >= end))) throw Error('status_expiry');
  const keys = loadOwnerKeys(env);
  // Revocation accepts either trusted Owner; activation requires both.
  for (const role of Object.keys(e.approvals)) {
    const a = e.approvals[role], k = keys.get(a?.key_id);
    if (!exact(a,['key_id','signature']) || !k || k.role !== role) throw Error('status_owner');
    const raw = Uint8Array.from(atob(a.signature), c=>c.charCodeAt(0));
    const key = await crypto.subtle.importKey('raw', ownedCryptoBuffer(k.public_key), {name:'Ed25519'}, false, ['verify']);
    if (!await crypto.subtle.verify('Ed25519', key, ownedCryptoBuffer(raw), ownedCryptoBuffer(new TextEncoder().encode(canonical(p))))) throw Error('status_signature');
  }
  if (d.head_sha256 !== await sha256(canonical(e))) throw Error('status_hash');
  return p;
}
export async function handleDelegationRequest(req: Request, deps: CasDependencies): Promise<Response> {
  const fail = casAuthGenerationFailure(req, deps.env);
  if (fail !== null) return reply(fail);
  const principal = identify(req.headers.get('authorization'), deps.env);
  if (!principal) return reply(401);
  const route = resolveFixedCasRoute(new URL(req.url).pathname);
  if (!route || route.handler !== 'delegation') return reply(404);
  const mode = route.key === DELEGATION_KEY ? 'formal' : 'test';
  if (mode !== principal.mode || !['owner','reader'].includes(principal.role)) return reply(403);
  if (req.method !== 'GET' && req.method !== 'PUT') return reply(405);
  if (req.method === 'PUT' && principal.role !== 'owner') return reply(403);
  if (!deps.store) return reply(503);
  try {
    if (req.method === 'GET') {
      const value = await deps.store.read(route.key);
      if (!value) return reply(404);
      await validateDelegationDocument(value.body,mode,deps.env);
      return new Response(value.body,{status:200,headers:{etag:`"${value.revision}"`,'cache-control':'no-store','content-type':'application/json'}});
    }
    if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(req.headers.get('content-type') ?? '')) return reply(415);
    const match = req.headers.get('if-match'), none = req.headers.get('if-none-match');
    if ((match === null) === (none === null)) return reply(428);
    if (none !== null && none !== '*') return reply(412);
    // Stream cap before parsing; oversized untrusted bodies cannot reach DB.
    const reader = req.body?.getReader(); if (!reader) return reply(409);
    const chunks: Uint8Array[] = []; let size = 0;
    for (;;) { const {value,done} = await reader.read(); if(done) break; size += value.length; if(size > 1048576) {await reader.cancel(); return reply(413);} chunks.push(value); }
    const bytes = new Uint8Array(size); let offset=0; for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
    const body = new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    let next; try {next = await validateDelegationDocument(body,mode,deps.env);} catch {return reply(409);}
    const prior = await deps.store.read(route.key);
    let revision;
    if (none === '*') {
      if(prior || next.sequence !== 1 || next.status !== 'ACTIVE') return reply(412);
      revision = await deps.store.insertIfAbsent(route.key,body);
    } else {
      if(!prior || match !== `"${prior.revision}"`) return reply(412);
      const old = await validateDelegationDocument(prior.body,mode,deps.env,false);
      if(old.status === 'REVOKED' || next.status !== 'REVOKED' || next.sequence !== old.sequence+1
          || ['delegation_id','contract_sha256','repository_id','execution_revision','environment'].some(k=>old[k]!==next[k])) return reply(409);
      revision = await deps.store.updateIfRevision(route.key,prior.revision,body);
    }
    return revision === undefined ? reply(412) : new Response(null,{status:204,headers:{etag:`"${revision}"`}});
  } catch { return reply(503); } // No retry even if a write may have committed.
}

import {beforeAll,describe,it,expect,vi} from 'vitest';
import {DAY,verifyEntitlement,evaluateAccess,deviceHash,HttpLicenseClient,isLicenseKey,pipeline,PipelineNotImplemented,type EntitlementClaims} from '../src/index.js';
const now=1_800_000_000; let privateKey:CryptoKey;let publicJwk:JsonWebKey;
const b64=(value:string|Uint8Array)=>Buffer.from(value).toString('base64url');
const claims=():EntitlementClaims=>({iss:'civoclip-license',aud:'civoclip-desktop',sub:'license-test',tier:'pro',licenseType:'perpetual_1y_updates',iat:now,exp:now+30*DAY,licenseExpiresAt:now+365*DAY,updatesUntil:now+365*DAY,device:'hash',features:['batch-export']});
async function sign(c:object=claims(),header:object={alg:'EdDSA',typ:'JWT',kid:'test-rotation'}){
 const h=b64(JSON.stringify(header)),p=b64(JSON.stringify(c));return `${h}.${p}.${b64(new Uint8Array(await crypto.subtle.sign('Ed25519',privateKey,new TextEncoder().encode(`${h}.${p}`))))}`;
}
beforeAll(async()=>{const pair=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as CryptoKeyPair;privateKey=pair.privateKey;publicJwk=await crypto.subtle.exportKey('jwk',pair.publicKey)});
const options=()=>({keys:{'test-rotation':publicJwk},now,device:'hash'});
describe('Ed25519 entitlement',()=>{
 it('verifies generated keys and rotated kid offline',async()=>{const c=await verifyEntitlement(await sign(),options());expect(c.tier).toBe('pro');expect(c.offlineExpiresAt).toBe(now+21*DAY);expect(c.fresh).toBe(true)});
 it('rejects tampering',async()=>{const t=(await sign()).split('.');t[1]=b64(JSON.stringify({...claims(),sub:'attacker'}));await expect(verifyEntitlement(t.join('.'),options())).rejects.toThrow('signature')});
 it('rejects a different public key',async()=>{const other=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as CryptoKeyPair;await expect(verifyEntitlement(await sign(),{...options(),keys:{'test-rotation':await crypto.subtle.exportKey('jwk',other.publicKey)}})).rejects.toThrow('signature')});
 it('rejects unknown kid',async()=>{await expect(verifyEntitlement(await sign(),{...options(),keys:{}})).rejects.toThrow('Unknown')});
 it('rejects non-EdDSA header',async()=>{await expect(verifyEntitlement(await sign(claims(),{alg:'HS256',typ:'JWT',kid:'test-rotation'}),options())).rejects.toThrow('header')});
 it.each(['iss','aud','tier','device'] as const)('rejects invalid %s',async field=>{await expect(verifyEntitlement(await sign({...claims(),[field]:'wrong'}),options())).rejects.toThrow()});
 it('rejects future issuance',async()=>{await expect(verifyEntitlement(await sign({...claims(),iat:now+1}),options())).rejects.toThrow()});
 it('keeps Pro and marks freshness at the exact default grace boundary',async()=>{
  const token=await sign();
  expect(await evaluateAccess(token,{...options(),now:now+21*DAY-1})).toMatchObject({tier:'pro',entitlement:{fresh:true}});
  expect(await evaluateAccess(token,{...options(),now:now+21*DAY})).toMatchObject({tier:'pro',entitlement:{fresh:false}});
 });
 it.each([14,30])('uses configured %d-day grace for freshness only',async grace=>{
  const token=await sign();
  expect(await evaluateAccess(token,{...options(),offlineGraceDays:grace,now:now+grace*DAY-1})).toMatchObject({tier:'pro',entitlement:{fresh:true}});
  expect(await evaluateAccess(token,{...options(),offlineGraceDays:grace,now:now+grace*DAY})).toMatchObject({tier:'pro',entitlement:{fresh:false}});
 });
 it.each([0,13,31,NaN])('rejects invalid grace %s',async grace=>{await expect(verifyEntitlement(await sign(),{...options(),offlineGraceDays:grace})).rejects.toThrow('grace')});
 it.each(['exp','licenseExpiresAt'] as const)('uses %s for freshness without removing Pro',async field=>{
  const token=await sign({...claims(),[field]:now+DAY});
  expect(await evaluateAccess(token,{...options(),now:now+DAY-1})).toMatchObject({tier:'pro',entitlement:{fresh:true,offlineExpiresAt:now+DAY}});
  expect(await evaluateAccess(token,{...options(),now:now+DAY})).toMatchObject({tier:'pro',entitlement:{fresh:false}});
 });
 it('verifies stale tokens after all freshness deadlines and update coverage have passed',async()=>{
  const token=await sign({...claims(),exp:now+DAY,licenseExpiresAt:now+2*DAY,updatesUntil:now+2*DAY});
  expect(await verifyEntitlement(token,{...options(),now:now+400*DAY})).toMatchObject({tier:'pro',fresh:false,updatesUntil:now+2*DAY});
 });
 it('keeps lifetime Pro without updatesUntil after all freshness deadlines',async()=>{
  const token=await sign({...claims(),licenseType:'lifetime',updatesUntil:undefined});
  expect(await evaluateAccess(token,options())).toMatchObject({tier:'pro',entitlement:{licenseType:'lifetime',fresh:true}});
  const access=await evaluateAccess(token,{...options(),now:now+400*DAY});
  expect(access).toMatchObject({tier:'pro',entitlement:{licenseType:'lifetime',fresh:false}});
  if(access.tier==='pro')expect(access.entitlement).not.toHaveProperty('updatesUntil');
 });
 it.each([now,null,'1800000000'])('rejects lifetime with updatesUntil %s',async updatesUntil=>{
  const token=await sign({...claims(),licenseType:'lifetime',updatesUntil});
  await expect(verifyEntitlement(token,options())).rejects.toThrow();
  expect((await evaluateAccess(token,options())).tier).toBe('free');
 });
 it.each([undefined,null,'unknown','Lifetime'])('rejects missing or unknown licenseType %s',async licenseType=>{
  const token=await sign({...claims(),licenseType});
  await expect(verifyEntitlement(token,options())).rejects.toThrow();
  expect((await evaluateAccess(token,options())).tier).toBe('free');
 });
 it.each([undefined,null,'1800000000',now-1,now+0.5,Number.MAX_SAFE_INTEGER+1])('rejects perpetual_1y_updates with malformed or missing updatesUntil %s',async updatesUntil=>{
  const token=await sign({...claims(),updatesUntil});
  await expect(verifyEntitlement(token,options())).rejects.toThrow();
  expect((await evaluateAccess(token,options())).tier).toBe('free');
 });
 it('accepts updatesUntil equal to iat',async()=>{
  expect(await verifyEntitlement(await sign({...claims(),updatesUntil:now}),options())).toMatchObject({updatesUntil:now});
 });
 it('missing or malformed token means free',async()=>{for(const token of [undefined,'','broken','a.b.c','null.null.null'])expect((await evaluateAccess(token,options())).tier).toBe('free')});
});
describe('provider-independent HTTP client',()=>{
 const key='CLIP-ABCD-EFGH-IJKL-MNOP',device={device_fingerprint:'machine-1',app_version:'0.1.0'};
 it('validates strict base32 format',()=>{expect(isLicenseKey(key)).toBe(true);for(const invalid of [key.toLowerCase(),'CLIP-0000-1111-8888-9999',key+'A',key+'\n','CLIP-ABCD-EFGH-IJKL'])expect(isLicenseKey(invalid)).toBe(false)});
 it('calls activate/refresh/deactivate and clears token',async()=>{const token=await sign({...claims(),device:await deviceHash(device.device_fingerprint)});const fetcher=vi.fn().mockImplementation(async()=>Response.json({token}));const client=new HttpLicenseClient('https://license.example.test',{keys:options().keys,now:()=>now,fetch:fetcher});await client.activate(key,device);await client.refresh(key,device);expect((await client.access()).tier).toBe('pro');await client.deactivate(key,device);expect((await client.access()).tier).toBe('free');expect(fetcher.mock.calls.map(c=>new URL(c[0]).pathname)).toEqual(['/api/license/activate','/api/license/refresh','/api/license/deactivate']);expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({key,...device})});
 it.each([401,403,404])('retains stale offline access on network errors and clears it on revocation %d',async status=>{let clock=now;const token=await sign({...claims(),device:await deviceHash(device.device_fingerprint)});const fetcher=vi.fn().mockResolvedValueOnce(Response.json({token})).mockRejectedValueOnce(new TypeError('offline')).mockResolvedValueOnce(Response.json({error:'revoked'},{status}));const client=new HttpLicenseClient('https://local.example.test',{keys:options().keys,now:()=>clock,fetch:fetcher});await client.activate(key,device);clock=now+400*DAY;await expect(client.refresh(key,device)).rejects.toThrow('offline');expect(await client.access()).toMatchObject({tier:'pro',entitlement:{fresh:false}});await expect(client.refresh(key,device)).rejects.toThrow(String(status));expect((await client.access()).tier).toBe('free')});
 it('requires fresh activation and refresh responses while retaining the valid cached token',async()=>{
  const token=await sign({...claims(),device:await deviceHash(device.device_fingerprint)});
  let clock=now+400*DAY;
  const fetcher=vi.fn().mockImplementation(async()=>Response.json({token}));
  const client=new HttpLicenseClient('https://local.example.test',{keys:options().keys,now:()=>clock,fetch:fetcher});
  await expect(client.activate(key,device)).rejects.toThrow('stale entitlement');
  expect((await client.access()).tier).toBe('free');
  clock=now;await client.activate(key,device);clock=now+400*DAY;
  await expect(client.refresh(key,device)).rejects.toThrow('stale entitlement');
  expect(await client.access()).toMatchObject({tier:'pro',entitlement:{fresh:false}});
 });
 it('rejects invalid server tokens and keys before trusting them',async()=>{const fetcher=vi.fn().mockResolvedValue(Response.json({token:'bad'}));const client=new HttpLicenseClient('http://localhost:3000',{fetch:fetcher});await expect(client.activate('invalid',device)).rejects.toThrow('Expected');expect(fetcher).not.toHaveBeenCalled();await expect(client.activate(key,device)).rejects.toThrow('invalid entitlement');expect((await client.access()).tier).toBe('free')});
 it('requires HTTPS except loopback',()=>{expect(()=>new HttpLicenseClient('http://remote.example.test')).toThrow('HTTPS');expect(()=>new HttpLicenseClient('http://localhost:3000')).not.toThrow()});
});
it('OSS stages are typed placeholders independent of licensing',async()=>{await expect(pipeline.ingest.ingest({uri:'file:///test.mp4'})).rejects.toBeInstanceOf(PipelineNotImplemented);await expect(pipeline.transcribe.transcribe({id:'a',source:{uri:'x'},durationSeconds:2})).rejects.toThrow('transcribe');await expect(pipeline.translate.translate({language:'en',segments:[]},'zh')).rejects.toThrow('translate');await expect(pipeline.highlightDetect.detect({language:'en',segments:[]})).rejects.toThrow('highlight');await expect(pipeline.clipExport.export({id:'a',source:{uri:'x'},durationSeconds:2},{start:0,end:1,score:1,title:'a'})).rejects.toThrow('clip/export')});

import {DurableObject} from "cloudflare:workers";
import {verifyPinnedSSHProof,verifyPinnedSSHSignature} from "../../../packages/protocol/src/proof";
import {ApiError,errorResponse,response,now,sha256hex,decodeBase64url,validNodeId} from "../../../packages/protocol/src/index";
interface Env {DB:D1Database;NODE_SESSIONS:DurableObjectNamespace;COMMAND_PUBLIC_KEY:string;}
function must(v:unknown,code:string,status=400):asserts v{if(!v)throw new ApiError(code,status);}
function plain(v:unknown):v is Record<string,unknown>{return !!v&&typeof v==="object"&&!Array.isArray(v);}
async function jsonBody(req:Request):Promise<Record<string,unknown>>{
  const s=await req.text();must(s.length<16384,"BODY_TOO_LARGE",413);
  let v:unknown;try{v=JSON.parse(s);}catch{throw new ApiError("INVALID_JSON");}
  must(plain(v),"INVALID_JSON");return v;
}
function path(req:Request){return new URL(req.url).pathname;}
async function verifyDevice(req:Request,env:Env):Promise<string>{
  const id=req.headers.get("X-Node-Id")||"";
  const ts=Number(req.headers.get("X-Device-Timestamp"));
  const nonce=req.headers.get("X-Device-Nonce")||"";
  const signature=req.headers.get("X-Device-Signature")||"";
  must(validNodeId(id)&&Number.isInteger(ts)&&Math.abs(now()-ts)<=60&&/^[A-Za-z0-9_-]{16,100}$/.test(nonce),"UNAUTHORIZED",401);
  const device=await env.DB.prepare("SELECT public_key FROM agent_credentials WHERE node_id=? AND revoked_at IS NULL").bind(id).first<{public_key:string}>();
  must(device,"UNAUTHORIZED",401);
  let pub:CryptoKey;
  try{pub=await crypto.subtle.importKey("raw",Uint8Array.from(decodeBase64url(device.public_key)),{name:"Ed25519"},false,["verify"]);}
  catch{throw new ApiError("UNAUTHORIZED",401);}
  const raw=req.method==="GET"?"":await req.clone().text();
  const digest=await sha256hex(raw);
  const message=[req.method,path(req),ts,nonce,digest].join("\n");
  let valid=false;try{valid=await crypto.subtle.verify({name:"Ed25519"},pub,Uint8Array.from(decodeBase64url(signature)),new TextEncoder().encode(message));}catch{}
  must(valid,"UNAUTHORIZED",401);
  const inserted=await env.DB.prepare("INSERT OR IGNORE INTO device_nonces(node_id,nonce,expires_at) VALUES (?,?,?)").bind(id,nonce,now()+120).run();
  must(inserted.meta.changes===1,"REPLAY",409);
  // Reclaim expired replay nonces opportunistically.
  if(Math.random()<0.02)await env.DB.prepare("DELETE FROM device_nonces WHERE expires_at<?").bind(now()).run();
  return id;
}
async function pair(req:Request,env:Env):Promise<Response>{
  const b=await jsonBody(req);
  const id=String(b.node_id||""),token=String(b.token||""),key=String(b.public_key||"");
  must(validNodeId(id)&&token.length>=32&&token.length<=150&&key.length>20,"INVALID_PAIRING");
  let raw:Uint8Array,signer:Uint8Array;
  try{raw=decodeBase64url(key);signer=decodeBase64url(env.COMMAND_PUBLIC_KEY||"");}
  catch{throw new ApiError("INVALID_DEVICE_KEY_OR_SIGNER");}
  must(raw.byteLength===32,"INVALID_DEVICE_KEY");
  // Do not consume the only recovery token if deployment is misconfigured.
  must(signer.byteLength===32,"SIGNER_NOT_CONFIGURED",503);
  const existing=await env.DB.prepare("SELECT node_id FROM agent_credentials WHERE node_id=?").bind(id).first();
  must(!existing,"NODE_ALREADY_PAIRED",409);
  const digest=await sha256hex(token),t=now();
  const statements=[
    env.DB.prepare(
      "INSERT OR IGNORE INTO agent_credentials(node_id,public_key,paired_at) SELECT ?,?,? WHERE EXISTS "+
      "(SELECT 1 FROM pairing_tokens WHERE node_id=? AND token_hash=? AND used_at IS NULL AND expires_at>?)"
    ).bind(id,key,t,id,digest,t),
    env.DB.prepare("UPDATE pairing_tokens SET used_at=? WHERE node_id=? AND token_hash=? AND used_at IS NULL AND expires_at>?")
      .bind(t,id,digest,t),
    env.DB.prepare("UPDATE nodes SET status='online',init_stage='PREFLIGHT',last_seen_at=? WHERE id=? AND EXISTS "+
      "(SELECT 1 FROM agent_credentials WHERE node_id=? AND public_key=?)").bind(t,id,id,key)
  ];
  // D1 batch is transactional: pairing token consumption and device binding
  // cannot be partially committed on DB failures.
  const [added,consumed]=await env.DB.batch(statements);
  must(added.meta.changes===1&&consumed.meta.changes===1,"INVALID_OR_EXPIRED_PAIRING",403);
  return response({node_id:id,command_signing_public_key:env.COMMAND_PUBLIC_KEY},201);
}
async function authenticated(req:Request,env:Env):Promise<Response>{
  const id=await verifyDevice(req,env),p=path(req);
  await env.DB.prepare("UPDATE nodes SET status='online',last_seen_at=? WHERE id=?").bind(now(),id).run();
  if(p==="/agent/v1/heartbeat"){
    const b=await jsonBody(req);
    const version=String(b.agent_version||"").slice(0,64),os=String(b.os_id||"").slice(0,64);
    await env.DB.prepare("UPDATE nodes SET agent_version=?,os_id=? WHERE id=?").bind(version,os,id).run();
    return response({ok:true,server_time:now()});
  }
  if(p==="/agent/v1/poll"){
    await env.DB.prepare("UPDATE operations SET status='EXPIRED' WHERE node_id=? AND status='CREATED' AND expires_at<=?").bind(id,now()).run();
    const op=await env.DB.prepare("SELECT * FROM operations WHERE node_id=? AND status='CREATED' AND expires_at>? ORDER BY created_at ASC LIMIT 1").bind(id,now()).first<any>();
    if(!op)return response({command:null});
    const taken=await env.DB.prepare("UPDATE operations SET status='DISPATCHED' WHERE id=? AND status='CREATED'").bind(op.id).run();
    if(taken.meta.changes!==1)return response({command:null});
    return response({command:op.command_json,signature:op.signature});
  }
  if(p==="/agent/v1/ssh-proof"){
    const b=await jsonBody(req);
    const payload=String(b.payload||""),signature=String(b.signature||"");
    must(payload.length>0&&payload.length<=4096&&signature.length<=128,"PROOF_TOO_LARGE");
    // Untrusted payload may only be used to LOOK UP matching D1 state. The
    // exact bytes are verified against an Owner-pinned per-node root key before
    // a single byte of verified state can be changed.
    let claim:any;
    try{claim=JSON.parse(payload);}catch{throw new ApiError("INVALID_PROOF_JSON");}
    must(plain(claim)&&validNodeId(String(claim.verification_id||""))&&
      validNodeId(String(claim.proof_id||"")),"INVALID_PROOF_ID");
    const trusted=await env.DB.prepare(
      "SELECT public_key FROM node_ssh_proof_keys WHERE node_id=?"
    ).bind(id).first<{public_key:string}>();
    must(trusted,"NODE_ROOT_PROOF_KEY_NOT_PINNED",403);
    const challenge=await env.DB.prepare(
      "SELECT id,node_id,public_key_id,login_user,key_fingerprint,config_revision,nonce_hash,"+
      "status,created_at,expires_at,prepared_at,proof_id,proof_hash FROM ssh_verifications WHERE id=? AND node_id=?"
    ).bind(String(claim.verification_id),id).first<any>();
    if(challenge?.status==="VERIFIED"&&
       challenge.proof_id===claim.proof_id&&
       challenge.proof_hash===await sha256hex(payload)){
      // A lost acknowledgement after a successful guarded D1 transition may
      // be safely retried. Still verify the owner's pinned root signature;
      // never re-run the status update or audit insertion.
      try{await verifyPinnedSSHSignature(payload,signature,trusted.public_key);}
      catch{throw new ApiError("INVALID_ROOT_PROOF_SIGNATURE",403);}
      return response({accepted:true,verification_id:challenge.id,status:"VERIFIED",idempotent:true});
    }
    must(challenge&&challenge.status==="PENDING"&&challenge.prepared_at!=null&&
      challenge.expires_at>now(),"CHALLENGE_NOT_ACTIVE",409);
    const node=await env.DB.prepare(
      "SELECT login_user,config_revision,init_stage FROM nodes WHERE id=?"
    ).bind(id).first<any>();
    const activeDaily=await env.DB.prepare(
      "SELECT id FROM public_keys WHERE purpose='daily' AND active=1"
    ).first<{id:string}>();
    must(node&&node.init_stage==="WAITING_VERIFICATION"&&
      node.login_user===challenge.login_user&&
      node.config_revision===challenge.config_revision&&
      activeDaily?.id===challenge.public_key_id,"CHALLENGE_CONTEXT_CHANGED",409);
    const expected={
      nodeId:id,verificationId:challenge.id,keyId:challenge.public_key_id,
      loginUser:challenge.login_user,fingerprint:challenge.key_fingerprint,
      configRevision:challenge.config_revision,nonceHash:challenge.nonce_hash,
      createdAt:challenge.created_at,expiresAt:challenge.expires_at,now:now()
    };
    let signed;
    try{
      signed=await verifyPinnedSSHProof(payload,signature,trusted.public_key,expected);
    }catch{
      throw new ApiError("ROOT_SSH_PROOF_SIGNATURE_OR_CONTEXT_INVALID",403);
    }
    const hash=await sha256hex(payload);
    // This guarded D1 state transition is the ONLY route to VERIFIED.
    // Replayed proofs and modified node/key/revision/expiry fail closed.
    const verified=await env.DB.prepare(
      "UPDATE ssh_verifications SET status='VERIFIED',verified_at=?,proof_id=?,proof_hash=? "+
      "WHERE id=? AND node_id=? AND status='PENDING' AND prepared_at IS NOT NULL "+
      "AND expires_at>? AND nonce_hash=? AND login_user=? AND key_fingerprint=? "+
      "AND config_revision=? AND public_key_id=? "+
      "AND EXISTS (SELECT 1 FROM nodes WHERE id=? AND login_user=? AND config_revision=? "+
      "AND init_stage='WAITING_VERIFICATION') "+
      "AND EXISTS (SELECT 1 FROM public_keys WHERE id=? AND purpose='daily' AND active=1)"
    ).bind(now(),signed.proof_id,hash,challenge.id,id,now(),
      challenge.nonce_hash,challenge.login_user,challenge.key_fingerprint,
      challenge.config_revision,challenge.public_key_id,
      id,challenge.login_user,challenge.config_revision,challenge.public_key_id).run();
    must(verified.meta.changes===1,"PROOF_ALREADY_USED_OR_CONTEXT_CHANGED",409);
    await env.DB.prepare(
      "UPDATE node_keys SET verified_at=? WHERE node_id=? AND public_key_id=? "+
      "AND login_user=? AND purpose='daily' AND state='installed'"
    ).bind(now(),id,challenge.public_key_id,challenge.login_user).run();
    await env.DB.prepare(
      "UPDATE nodes SET init_stage='KEY_VERIFIED' WHERE id=? AND init_stage='WAITING_VERIFICATION' "+
      "AND config_revision=?"
    ).bind(id,challenge.config_revision).run();
    await env.DB.prepare(
      "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
      "VALUES (?,?,?,'ssh.verification.proof',NULL,'VERIFIED',?,?)"
    ).bind(crypto.randomUUID(),String(challenge.id),id,
      "proof_id="+signed.proof_id,now()).run();
    return response({accepted:true,verification_id:challenge.id,status:"VERIFIED"});
  }
  if(p==="/agent/v1/report"){
    const b=await jsonBody(req);
    const opId=String(b.operation_id||""),status=String(b.status||"");
    must(validNodeId(opId)&&["RUNNING","SUCCEEDED","FAILED"].includes(status),"INVALID_REPORT");
    const op=await env.DB.prepare("SELECT id,action,status,operator_id,command_json FROM operations WHERE id=? AND node_id=?").bind(opId,id).first<any>();
    must(op,"OPERATION_NOT_FOUND",404);
    const allowed=status==="RUNNING"?["DISPATCHED"]:["DISPATCHED","RUNNING"];
    must(allowed.includes(op.status),"INVALID_STATUS_TRANSITION",409);
    if(status==="SUCCEEDED"&&op.action==="ssh.policy.inspect"){
      const c=JSON.parse(op.command_json);
      must(b.detail&&plain(b.detail)&&
        typeof b.detail.revision==="string"&&/^[a-f0-9]{64}$/.test(b.detail.revision)&&
        b.detail.login_user===c.payload.login_user&&
        b.detail.verified_login===false&&
        b.result_code==="POLICY_INSPECTED",
        "INVALID_POLICY_REPORT",409);
    }
    if(status==="SUCCEEDED"&&op.action==="ssh.verification.prepare"){
      const c=JSON.parse(op.command_json);
      must(b.result_code==="VERIFICATION_PREPARED"&&b.detail&&plain(b.detail)&&
        b.detail.verification_id===c.payload.verification_id&&
        b.detail.verified_login===false,"INVALID_PREPARATION_REPORT",409);
      const current=await env.DB.prepare(
        "SELECT id,config_revision,login_user,key_fingerprint,public_key_id FROM ssh_verifications "+
        "WHERE id=? AND node_id=? AND status='PENDING' AND expires_at>?"
      ).bind(c.payload.verification_id,id,now()).first<{
        id:string;config_revision:string;login_user:string;key_fingerprint:string;public_key_id:string;
      }>();
      must(current&&current.config_revision===c.payload.config_revision&&
        current.login_user===c.payload.login_user&&
        current.key_fingerprint===c.payload.fingerprint&&
        current.public_key_id===c.payload.key_id,"VERIFICATION_PREPARATION_STALE",409);
    }
    // Validate helper proof BEFORE setting a sensitive operation to SUCCEEDED.
    if(status==="SUCCEEDED"&&op.action==="ssh.daily.install"){
      const c=JSON.parse(op.command_json);
      must(b.detail&&plain(b.detail)&&b.detail.key_fingerprint===c.payload.fingerprint&&b.detail.file_checked===true,
        "INSTALL_PROOF_MISSING",409);
    }
    const detail=JSON.stringify(b.detail||{}).slice(0,3500);
    const changes=await env.DB.prepare("UPDATE operations SET status=?,result_code=?,detail=?,finished_at=? WHERE id=? AND node_id=? AND status IN ("+
      allowed.map(()=>"?").join(",")+")")
      .bind(status,String(b.result_code||"").slice(0,64),detail,status==="RUNNING"?null:now(),opId,id,...allowed).run();
    must(changes.meta.changes===1,"INVALID_STATUS_TRANSITION",409);
    if(op.action==="ssh.verification.prepare"&&status!=="RUNNING"){
      const c=JSON.parse(op.command_json);
      if(status==="SUCCEEDED"){
        await env.DB.prepare(
          "UPDATE ssh_verifications SET prepared_at=? WHERE id=? AND node_id=? AND status='PENDING' AND expires_at>?"
        ).bind(now(),c.payload.verification_id,id,now()).run();
      }else{
        // A failed helper preparation cannot later be mistaken for a usable
        // verification challenge. It never grants login or SSH permissions.
        await env.DB.prepare(
          "UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? "+
          "WHERE id=? AND node_id=? AND status='PENDING'"
        ).bind(now(),c.payload.verification_id,id).run();
      }
    }
    if(status==="SUCCEEDED"&&op.action==="ssh.policy.inspect"&&plain(b.detail)){
      const previous=await env.DB.prepare("SELECT config_revision,init_stage FROM nodes WHERE id=?")
        .bind(id).first<{config_revision:string;init_stage:string}>();
      must(previous,"NODE_NOT_FOUND",404);
      const revision=String(b.detail.revision);
      // A repeated inspection of the SAME policy must not erase a successful
      // daily-key install or strand an already issued challenge.
      const preserve=previous.init_stage==="WAITING_VERIFICATION"&&previous.config_revision===revision;
      const steps=[
        env.DB.prepare("UPDATE nodes SET config_revision=?,init_stage=? WHERE id=?")
          .bind(revision,preserve?"WAITING_VERIFICATION":"POLICY_INSPECTED",id)
      ];
      if(previous.config_revision!==revision){
        steps.push(env.DB.prepare(
          "UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? "+
          "WHERE node_id=? AND status='PENDING'"
        ).bind(now(),id));
      }
      await env.DB.batch(steps);
    }
    if(status==="SUCCEEDED"&&op.action==="ssh.daily.install"){
      const c=JSON.parse(op.command_json);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO node_keys(id,node_id,public_key_id,login_user,purpose,state) VALUES (?,?,?,?,'daily','installed')")
          .bind(crypto.randomUUID(),id,c.payload.key_id,c.payload.login_user),
        env.DB.prepare("UPDATE nodes SET init_stage='WAITING_VERIFICATION' WHERE id=?").bind(id),
        // A new installation changes the challenge's security context.
        env.DB.prepare("UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? WHERE node_id=? AND status='PENDING'")
          .bind(now(),id)
      ]);
    }
    if(status!=="RUNNING"){
      await env.DB.prepare("INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) VALUES (?,?,?,?,?,?,?,?)")
        .bind(crypto.randomUUID(),op.operator_id,id,op.action,opId,status,String(b.result_code||"").slice(0,64),now()).run();
    }
    return response({accepted:true});
  }
  if(p==="/agent/v1/ws"){
    must(req.headers.get("Upgrade")?.toLowerCase()==="websocket","WEBSOCKET_REQUIRED",426);
    const session=env.NODE_SESSIONS.get(env.NODE_SESSIONS.idFromName(id));
    return session.fetch(new Request("https://node.internal/connect",{headers:{Upgrade:"websocket"}}));
  }
  throw new ApiError("NOT_FOUND",404);
}
export default {
  async fetch(req:Request,env:Env):Promise<Response>{
    try{
      const p=path(req);
      if(p==="/agent/v1/pair"&&req.method==="POST")return await pair(req,env);
      if(p.startsWith("/agent/v1/")&&["POST","GET"].includes(req.method))return await authenticated(req,env);
      return response({error:"NOT_FOUND"},404);
    }catch(e){return errorResponse(e);}
  }
};
export class NodeSession extends DurableObject<Env> {
  async fetch(req:Request):Promise<Response>{
    const p=path(req);
    if(p==="/connect"&&req.headers.get("Upgrade")?.toLowerCase()==="websocket"){
      const pair=new WebSocketPair();const client=pair[0],server=pair[1];
      this.ctx.acceptWebSocket(server);
      return new Response(null,{status:101,webSocket:client});
    }
    if(p==="/dispatch"&&req.method==="POST"){
      const data=await req.text();let count=0;
      for(const ws of this.ctx.getWebSockets()){try{ws.send(data);count++;}catch{}}
      return response({delivered:count});
    }
    return response({error:"NOT_FOUND"},404);
  }
  async webSocketMessage(ws:WebSocket,message:string|ArrayBuffer):Promise<void>{
    if(typeof message!=="string")return;
    if(message==="ping"){ws.send("pong");}
  }
}

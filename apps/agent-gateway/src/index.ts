import {DurableObject} from "cloudflare:workers";
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

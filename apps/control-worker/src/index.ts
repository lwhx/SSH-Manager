import {createRemoteJWKSet,jwtVerify} from "jose";
import {ApiError,errorResponse,response,now,safeHost,safeUser,validNodeId,parsePublicKey,sha256hex,base64url,signCommand} from "../../../packages/protocol/src/index";

interface Env {
  DB:D1Database; NODE_SESSIONS:DurableObjectNamespace; ASSETS:Fetcher;
  ACCESS_TEAM_DOMAIN:string; ACCESS_AUD:string; BOOTSTRAP_OWNER_EMAIL:string;
  COMMAND_PRIVATE_KEY:string;
}
interface Actor {id:string; email:string; role:string; subject:string;}
const jsonLimit=8192;
const allowedMethods=new Set(["GET","POST","PUT"]);
function ensure(condition:unknown,code:string,status=400):asserts condition {if(!condition)throw new ApiError(code,status);}
async function bodyJSON(req:Request):Promise<Record<string,unknown>> {
  const txt=await req.text();
  ensure(txt.length<=jsonLimit,"BODY_TOO_LARGE",413);
  let obj:unknown;try{obj=JSON.parse(txt);}catch{throw new ApiError("INVALID_JSON");}
  ensure(!!obj&&typeof obj==="object"&&!Array.isArray(obj),"INVALID_JSON");
  return obj as Record<string,unknown>;
}
async function actor(req:Request,env:Env):Promise<Actor>{
  ensure(env.ACCESS_TEAM_DOMAIN&&env.ACCESS_AUD&&env.BOOTSTRAP_OWNER_EMAIL,"ACCESS_NOT_CONFIGURED",503);
  const jwt=req.headers.get("Cf-Access-Jwt-Assertion");
  ensure(jwt,"UNAUTHORIZED",401);
  const url=new URL("https://"+env.ACCESS_TEAM_DOMAIN+"/cdn-cgi/access/certs");
  let claims;
  try {
    const result=await jwtVerify(jwt,createRemoteJWKSet(url),{
      issuer:"https://"+env.ACCESS_TEAM_DOMAIN,audience:env.ACCESS_AUD,
      algorithms:["RS256"]
    });
    claims=result.payload;
  }catch{throw new ApiError("UNAUTHORIZED",401);}
  const subject=String(claims.sub||"");
  const email=String(claims.email||"").toLowerCase();
  ensure(subject.length>8&&email.includes("@"),"UNAUTHORIZED",401);
  let identity=await env.DB.prepare("SELECT u.id,u.email,u.role,u.status FROM user_identities i JOIN users u ON i.user_id=u.id WHERE i.subject=?").bind(subject).first<{id:string;email:string;role:string;status:string}>();
  if(!identity&&email===env.BOOTSTRAP_OWNER_EMAIL.toLowerCase()){
    const user=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first<{id:string;role:string;status:string}>();
    const id=user?.id||crypto.randomUUID();
    if(!user)await env.DB.prepare("INSERT INTO users(id,email,role,status,created_at) VALUES (?,?,'owner','active',?)").bind(id,email,now()).run();
    await env.DB.prepare("INSERT OR IGNORE INTO user_identities(subject,user_id,provider,created_at) VALUES (?,?,?,?)").bind(subject,id,"access",now()).run();
    identity={id,email,role:"owner",status:"active"};
  }
  ensure(identity?.status==="active","FORBIDDEN",403);
  return {id:identity.id,email:identity.email,role:identity.role,subject};
}
function needRole(user:Actor,minimum:"viewer"|"admin"|"owner"){
  const ranks:{[k:string]:number}={viewer:0,admin:1,owner:2};
  ensure((ranks[user.role]??-1)>=ranks[minimum],"FORBIDDEN",403);
}
function safeRequest(req:Request){
  if(req.method==="GET")return;
  ensure(allowedMethods.has(req.method),"METHOD_NOT_ALLOWED",405);
  const origin=req.headers.get("Origin");
  ensure(origin===new URL(req.url).origin,"INVALID_ORIGIN",403);
  ensure(req.headers.get("Content-Type")?.includes("application/json"),"INVALID_CONTENT_TYPE",415);
}
async function audit(env:Env,a:Actor,node:string|null,action:string,result:string,reason:string|null=null,op:string|null=null){
  await env.DB.prepare("INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) VALUES (?,?,?,?,?,?,?,?)")
    .bind(crypto.randomUUID(),a.id,node,action,op,result,reason,now()).run();
}
async function findNode(env:Env,id:string){
  ensure(validNodeId(id),"NODE_NOT_FOUND",404);
  const n=await env.DB.prepare("SELECT * FROM nodes WHERE id=?").bind(id).first<any>();
  ensure(n,"NODE_NOT_FOUND",404);return n;
}
function isOnline(node:any){return node.status==="online"&&Number(node.last_seen_at)>now()-90;}
async function freshPairToken(env:Env,user:Actor,nodeId:string){
  const token=base64url(crypto.getRandomValues(new Uint8Array(32)));
  const hash=await sha256hex(token);
  await env.DB.prepare("DELETE FROM pairing_tokens WHERE node_id=? AND used_at IS NULL").bind(nodeId).run();
  await env.DB.prepare("INSERT INTO pairing_tokens(id,node_id,token_hash,expires_at,created_by) VALUES (?,?,?,?,?)")
    .bind(crypto.randomUUID(),nodeId,hash,now()+600,user.id).run();
  await audit(env,user,nodeId,"node.pairing_token","created");
  return {token,expires_in:600};
}
async function handle(req:Request,env:Env):Promise<Response>{
  const url=new URL(req.url);
  const p=url.pathname;
  if(p==="/api/v1/health")return response({status:"ok",version:"0.1.0",ssh_writes_enabled:false});
  const a=await actor(req,env);safeRequest(req);
  if(p==="/api/v1/me"&&req.method==="GET")return response({id:a.id,email:a.email,role:a.role});
  if(p==="/api/v1/nodes"&&req.method==="GET"){
    const q=await env.DB.prepare("SELECT id,name,ssh_host,ssh_port,login_user,status,init_stage,config_revision,agent_version,os_id,last_seen_at,created_at FROM nodes ORDER BY created_at DESC").all();
    return response({nodes:q.results});
  }
  if(p==="/api/v1/nodes"&&req.method==="POST"){
    needRole(a,"admin");const b=await bodyJSON(req);
    const name=String(b.name||"").trim(),host=String(b.ssh_host||"").trim(),login=String(b.login_user||"").trim();
    const port=Number(b.ssh_port||22);
    ensure(name.length>=1&&name.length<=80&&safeHost(host)&&safeUser(login)&&Number.isInteger(port)&&port>0&&port<65536,"INVALID_NODE");
    const id=crypto.randomUUID();
    await env.DB.prepare("INSERT INTO nodes(id,name,ssh_host,ssh_port,login_user,created_at) VALUES (?,?,?,?,?,?)")
      .bind(id,name,host,port,login,now()).run();
    await audit(env,a,id,"node.create","ok");
    return response({node_id:id,...await freshPairToken(env,a,id)},201);
  }
  const nodeMatch=/^\/api\/v1\/nodes\/([a-f0-9-]{36})(?:\/(.+))?$/.exec(p);
  if(nodeMatch){
    const node=await findNode(env,nodeMatch[1]),sub=nodeMatch[2]||"";
    if(!sub&&req.method==="GET")return response({node});
    if(sub==="pairing-token"&&req.method==="POST"){
      needRole(a,"admin");
      ensure(node.status==="unpaired","NODE_ALREADY_PAIRED",409);
      return response(await freshPairToken(env,a,node.id));
    }
    if(sub==="daily-key/install"&&req.method==="POST"){
      needRole(a,"admin");ensure(isOnline(node),"NODE_OFFLINE",409);
      const key=await env.DB.prepare("SELECT * FROM public_keys WHERE purpose='daily' AND active=1").first<any>();
      ensure(key,"DAILY_KEY_MISSING",409);
      const idem=req.headers.get("Idempotency-Key");
      ensure(idem&&/^[a-zA-Z0-9_-]{12,100}$/.test(idem),"IDEMPOTENCY_KEY_REQUIRED");
      const exists=await env.DB.prepare("SELECT id,status FROM operations WHERE operator_id=? AND idempotency_key=?").bind(a.id,idem).first<any>();
      if(exists)return response({operation_id:exists.id,status:exists.status});
      ensure(env.COMMAND_PRIVATE_KEY,"SIGNER_NOT_CONFIGURED",503);
      const id=crypto.randomUUID(),t=now();
      const cmd={v:1 as const,id,node_id:node.id,action:"ssh.daily.install" as const,actor:a.id,issued_at:t,expires_at:t+45,expected_revision:node.config_revision,payload:{login_user:node.login_user,public_key:key.public_key,key_id:key.id,fingerprint:key.fingerprint}};
      const signed=await signCommand(cmd,env.COMMAND_PRIVATE_KEY);
      await env.DB.prepare("INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,expected_revision,command_json,signature,status,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
        .bind(id,node.id,cmd.action,a.id,idem,node.config_revision,signed.command,signed.signature,"CREATED",t,t+45).run();
      await audit(env,a,node.id,cmd.action,"requested",null,id);
      // Reserve delivery before WSS dispatch. If no websocket received it,
      // safely release to HTTPS poll; a completed command is never re-queued.
      try{
        await env.DB.prepare("UPDATE operations SET status='DISPATCHED' WHERE id=? AND status='CREATED'").bind(id).run();
        const stub=env.NODE_SESSIONS.get(env.NODE_SESSIONS.idFromName(node.id));
        const delivered=await stub.fetch("https://node.internal/dispatch",{method:"POST",body:JSON.stringify(signed)});
        const value=await delivered.json() as {delivered?:number};
        if(!value.delivered)await env.DB.prepare("UPDATE operations SET status='CREATED' WHERE id=? AND status='DISPATCHED'").bind(id).run();
      }catch{
        await env.DB.prepare("UPDATE operations SET status='CREATED' WHERE id=? AND status='DISPATCHED'").bind(id).run();
      }
      return response({operation_id:id,status:"CREATED"},202);
    }
    if(sub==="snapshots"&&req.method==="GET"){
      needRole(a,"admin");const snapshots=await env.DB.prepare("SELECT * FROM ssh_config_snapshots WHERE node_id=? ORDER BY created_at DESC").bind(node.id).all();
      return response({snapshots:snapshots.results});
    }
    if(sub.startsWith("rescue/")||sub.startsWith("ssh/")||sub.includes("restore")||sub==="verifications"){
      needRole(a,"owner");
      // Fail closed until end-to-end proof and the privileged helper are validated.
      await audit(env,a,node.id,sub,"blocked","NOT_IMPLEMENTED");
      throw new ApiError("FEATURE_LOCKED_PENDING_SSH_E2E",501);
    }
  }
  if(p==="/api/v1/keys"&&req.method==="GET"){
    needRole(a,"admin");const keys=await env.DB.prepare("SELECT id,purpose,name,algorithm,public_key,fingerprint,version,created_at FROM public_keys WHERE active=1 ORDER BY purpose").all();
    return response({keys:keys.results});
  }
  const keyMatch=/^\/api\/v1\/keys\/(daily|rescue)$/.exec(p);
  if(keyMatch&&req.method==="PUT"){
    needRole(a,"owner");const b=await bodyJSON(req);
    ensure(typeof b.public_key==="string" && b.public_key.length<2048,"KEY_INVALID");
    const key=await parsePublicKey(b.public_key);
    const purpose=keyMatch[1],version=Number((await env.DB.prepare("SELECT max(version) AS v FROM public_keys WHERE purpose=?").bind(purpose).first<{v:number|null}>())?.v||0)+1;
    const id=crypto.randomUUID(),name=String(b.name||purpose).slice(0,80);
    // A D1 batch is transactional; changing global settings NEVER installs keys.
    await env.DB.batch([
      env.DB.prepare("UPDATE public_keys SET active=0 WHERE purpose=?").bind(purpose),
      env.DB.prepare("INSERT INTO public_keys(id,purpose,name,algorithm,public_key,fingerprint,version,active,created_by,created_at) VALUES (?,?,?,?,?,?,?,1,?,?)").bind(id,purpose,name,key.algorithm,key.normalized,key.fingerprint,version,a.id,now())
    ]);
    await audit(env,a,null,"keys."+purpose+".update","ok");
    return response({id,purpose,fingerprint:key.fingerprint,version,installed_nodes:0});
  }
  const opMatch=/^\/api\/v1\/operations\/([a-f0-9-]{36})$/.exec(p);
  if(opMatch&&req.method==="GET"){
    const op=await env.DB.prepare("SELECT id,node_id,action,status,result_code,detail,created_at,expires_at,finished_at FROM operations WHERE id=?").bind(opMatch[1]).first();
    ensure(op,"OPERATION_NOT_FOUND",404);return response({operation:op});
  }
  if(p==="/api/v1/audit"&&req.method==="GET"){
    needRole(a,"owner");
    const q=await env.DB.prepare("SELECT actor_id,node_id,action,operation_id,result,reason,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100").all();
    return response({entries:q.results});
  }
  throw new ApiError("NOT_FOUND",404);
}
export default {
  async fetch(req:Request,env:Env):Promise<Response> {
    if(new URL(req.url).pathname.startsWith("/api/")){
      try{return await handle(req,env);}catch(e){return errorResponse(e);}
    }
    return env.ASSETS.fetch(req);
  }
};

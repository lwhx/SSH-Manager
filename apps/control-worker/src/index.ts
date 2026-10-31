import {createRemoteJWKSet,jwtVerify} from "jose";
import {verificationBlocker,verificationStatus,VERIFICATION_TTL_SECONDS} from "../../../packages/protocol/src/verification";
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
interface AccessIdentity {subject:string;email:string;}
async function verifiedAccess(req:Request,env:Env):Promise<AccessIdentity>{
  ensure(env.ACCESS_TEAM_DOMAIN&&env.ACCESS_AUD&&env.BOOTSTRAP_OWNER_EMAIL,"ACCESS_NOT_CONFIGURED",503);
  const jwt=req.headers.get("Cf-Access-Jwt-Assertion");
  ensure(jwt,"UNAUTHORIZED",401);
  const url=new URL("https://"+env.ACCESS_TEAM_DOMAIN+"/cdn-cgi/access/certs");
  let claims;
  try{
    const result=await jwtVerify(jwt,createRemoteJWKSet(url),{
      issuer:"https://"+env.ACCESS_TEAM_DOMAIN,audience:env.ACCESS_AUD,
      algorithms:["RS256"]
    });
    claims=result.payload;
  }catch{throw new ApiError("UNAUTHORIZED",401);}
  const subject=String(claims.sub||"");
  const email=String(claims.email||"").trim().toLowerCase();
  ensure(subject.length>8&&email.includes("@"),"UNAUTHORIZED",401);
  return {subject,email};
}
async function actor(req:Request,env:Env):Promise<Actor>{
  const {subject,email}=await verifiedAccess(req,env);
  let identity=await env.DB.prepare(
    "SELECT u.id,u.email,u.role,u.status FROM user_identities i JOIN users u ON i.user_id=u.id WHERE i.subject=?"
  ).bind(subject).first<{id:string;email:string;role:string;status:string}>();
  // First login bootstraps ONLY the first verified Access subject. Never
  // silently attach another identity provider because its email matches.
  if(!identity&&email===env.BOOTSTRAP_OWNER_EMAIL.toLowerCase()){
    const existing=await env.DB.prepare("SELECT id FROM users WHERE email=? LIMIT 1").bind(email).first();
    if(!existing){
      const id=crypto.randomUUID();
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users(id,email,role,status,created_at) VALUES (?,?,'owner','active',?)").bind(id,email,now()),
        env.DB.prepare("INSERT INTO user_identities(subject,user_id,provider,created_at) VALUES (?,?,?,?)").bind(subject,id,"cloudflare-access",now())
      ]);
      identity={id,email,role:"owner",status:"active"};
    }
  }
  ensure(identity?.status==="active","FORBIDDEN",403);
  return {id:identity.id,email:identity.email,role:identity.role,subject};
}
async function claimIdentity(req:Request,env:Env):Promise<Response>{
  // Deliberately available to Access-verified users WITHOUT an SSH Manager
  // membership, but only with a one-time Owner-issued 256-bit linking token.
  const identity=await verifiedAccess(req,env), b=await bodyJSON(req);
  const token=String(b.token||"");
  ensure(/^[a-zA-Z0-9_-]{40,64}$/.test(token),"INVALID_LINK_TOKEN",403);
  const tokenHash=await sha256hex(token),t=now();
  const row=await env.DB.prepare("SELECT t.id,t.user_id,u.email,u.status FROM identity_link_tokens t JOIN users u ON t.user_id=u.id WHERE t.token_hash=? AND t.used_at IS NULL AND t.expires_at>?")
    .bind(tokenHash,t).first<{id:string;user_id:string;email:string;status:string}>();
  ensure(row&&row.status==="active"&&row.email.toLowerCase()===identity.email,"INVALID_LINK_TOKEN",403);
  const bound=await env.DB.prepare("SELECT user_id FROM user_identities WHERE subject=?").bind(identity.subject).first();
  ensure(!bound,"IDENTITY_ALREADY_LINKED",409);
  // The insertion is conditional on an unused token; the following update
  // consumes it in the SAME D1 transaction. Concurrent claims cannot both win.
  const [added,consumed]=await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO user_identities(subject,user_id,provider,created_at) SELECT ?,?,'cloudflare-access',? WHERE EXISTS "+
      "(SELECT 1 FROM identity_link_tokens WHERE id=? AND token_hash=? AND used_at IS NULL AND expires_at>?)")
      .bind(identity.subject,row.user_id,t,row.id,tokenHash,t),
    env.DB.prepare("UPDATE identity_link_tokens SET used_at=? WHERE id=? AND token_hash=? AND used_at IS NULL AND expires_at>?")
      .bind(t,row.id,tokenHash,t)
  ]);
  ensure(added.meta.changes===1&&consumed.meta.changes===1,"INVALID_LINK_TOKEN",403);
  await env.DB.prepare("INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) VALUES (?,?,NULL,'identity.link',NULL,'success',NULL,?)")
    .bind(crypto.randomUUID(),row.user_id,t).run();
  return response({linked:true});
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

async function queueNodeOperation(
  req:Request, env:Env, a:Actor, node:any,
  action:"node.preflight"|"ssh.policy.inspect"|"ssh.daily.install"|"ssh.verification.prepare", payload:Record<string,unknown>
):Promise<Response>{
  ensure(isOnline(node),"NODE_OFFLINE",409);
  const idem=req.headers.get("Idempotency-Key");
  ensure(idem&&/^[a-zA-Z0-9_-]{12,100}$/.test(idem),"IDEMPOTENCY_KEY_REQUIRED");
  const exists=await env.DB.prepare("SELECT id,status FROM operations WHERE operator_id=? AND idempotency_key=?").bind(a.id,idem).first<any>();
  if(exists)return response({operation_id:exists.id,status:exists.status});
  ensure(env.COMMAND_PRIVATE_KEY,"SIGNER_NOT_CONFIGURED",503);
  await env.DB.prepare("UPDATE operations SET status='EXPIRED' WHERE node_id=? AND status='CREATED' AND expires_at<=?").bind(node.id,now()).run();
  const pending=await env.DB.prepare("SELECT id FROM operations WHERE node_id=? AND status IN ('CREATED','DISPATCHED','RUNNING') AND expires_at>? LIMIT 1").bind(node.id,now()).first();
  ensure(!pending,"NODE_OPERATION_IN_PROGRESS",409);
  const id=crypto.randomUUID(),t=now();
  const cmd={v:1 as const,id,node_id:node.id,action,actor:a.id,issued_at:t,expires_at:t+45,expected_revision:node.config_revision,payload};
  const signed=await signCommand(cmd,env.COMMAND_PRIVATE_KEY);
  await env.DB.prepare("INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,expected_revision,command_json,signature,status,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .bind(id,node.id,action,a.id,idem,node.config_revision,signed.command,signed.signature,"CREATED",t,t+45).run();
  await audit(env,a,node.id,action,"requested",null,id);
  await dispatchPreparedOperation(env,node.id,id,signed);
  return response({operation_id:id,status:"QUEUED"},202);
}

async function dispatchPreparedOperation(env:Env,nodeId:string,operationId:string,signed:{command:string;signature:string}):Promise<void>{
  // WSS is opportunistic; if no WSS session accepted delivery, HTTPS poll takes over.
  try{
    await env.DB.prepare("UPDATE operations SET status='DISPATCHED' WHERE id=? AND status='CREATED'").bind(operationId).run();
    const stub=env.NODE_SESSIONS.get(env.NODE_SESSIONS.idFromName(nodeId));
    const delivered=await stub.fetch("https://node.internal/dispatch",{method:"POST",body:JSON.stringify(signed)});
    const value=await delivered.json() as {delivered?:number};
    if(!value.delivered)await env.DB.prepare("UPDATE operations SET status='CREATED' WHERE id=? AND status='DISPATCHED'").bind(operationId).run();
  }catch{
    await env.DB.prepare("UPDATE operations SET status='CREATED' WHERE id=? AND status='DISPATCHED'").bind(operationId).run();
  }
}

async function handle(req:Request,env:Env):Promise<Response>{
  const url=new URL(req.url);
  const p=url.pathname;
  if(p==="/api/v1/health")return response({status:"ok",version:"0.1.0",ssh_writes_enabled:false});
  if(p==="/api/v1/identity/link-claim"&&req.method==="POST"){
    safeRequest(req);return claimIdentity(req,env);
  }
  const a=await actor(req,env);safeRequest(req);
  if(p==="/api/v1/identity/link-start"&&req.method==="POST"){
    needRole(a,"owner");
    const token=base64url(crypto.getRandomValues(new Uint8Array(32)));
    const digest=await sha256hex(token),t=now();
    await env.DB.prepare("INSERT INTO identity_link_tokens(id,user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?,?)")
      .bind(crypto.randomUUID(),a.id,digest,t+300,t).run();
    await audit(env,a,null,"identity.link_token","created");
    return response({token,expires_in:300});
  }
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
    if(sub==="ssh-proof-key"&&req.method==="GET"){
      needRole(a,"admin");
      const pinned=await env.DB.prepare(
        "SELECT public_key,fingerprint,created_at FROM node_ssh_proof_keys WHERE node_id=?"
      ).bind(node.id).first();
      return response({pinned});
    }
    if(sub==="ssh-proof-key"&&req.method==="POST"){
      needRole(a,"owner");
      const b=await bodyJSON(req);
      ensure(b.confirm_node_id===node.id,"NODE_CONFIRMATION_REQUIRED",403);
      const publicKey=String(b.public_key||"");
      ensure(/^[A-Za-z0-9_-]{43}$/.test(publicKey),"INVALID_PROOF_PUBLIC_KEY",400);
      let raw:Uint8Array;
      try{raw=decodeBase64url(publicKey);}
      catch{throw new ApiError("INVALID_PROOF_PUBLIC_KEY",400);}
      ensure(raw.length===32,"INVALID_PROOF_PUBLIC_KEY",400);
      // The owner must separately inspect the key printed by the root VPS
      // helper. The Agent cannot register or replace this trust anchor.
      const canonical=base64url(raw);
      ensure(publicKey===canonical,"NON_CANONICAL_PROOF_KEY",400);
      const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",Uint8Array.from(raw)));
      const fingerprint="SHA256:"+btoa(String.fromCharCode(...digest)).replace(/=+$/,"");
      ensure(b.confirm_fingerprint===fingerprint,"PROOF_FINGERPRINT_CONFIRMATION_REQUIRED",403);
      const result=await env.DB.prepare(
        "INSERT OR IGNORE INTO node_ssh_proof_keys(node_id,public_key,fingerprint,approved_by,created_at) "+
        "VALUES (?,?,?,?,?)"
      ).bind(node.id,publicKey,fingerprint,a.id,now()).run();
      ensure(result.meta.changes===1,"NODE_PROOF_KEY_ALREADY_PINNED",409);
      await audit(env,a,node.id,"ssh.proof-key.pin","ok");
      return response({node_id:node.id,fingerprint,pinned:true},201);
    }
    if(sub==="preflight"&&req.method==="POST"){
      needRole(a,"admin");
      return queueNodeOperation(req,env,a,node,"node.preflight",{login_user:node.login_user,ssh_port:node.ssh_port});
    }
    if(sub==="ssh-policy/inspect"&&req.method==="POST"){
      needRole(a,"admin");
      return queueNodeOperation(req,env,a,node,"ssh.policy.inspect",{login_user:node.login_user,ssh_port:node.ssh_port});
    }
    if(sub==="daily-key/install"&&req.method==="POST"){
      needRole(a,"admin");
      // The Agent must still reject privileged SSH writes while the P3 helper
      // and authenticated login-proof workflow are incomplete.
      const key=await env.DB.prepare("SELECT * FROM public_keys WHERE purpose='daily' AND active=1").first<any>();
      ensure(key,"DAILY_KEY_MISSING",409);
      ensure(node.config_revision!=="unverified","POLICY_INSPECTION_REQUIRED",409);
      return queueNodeOperation(req,env,a,node,"ssh.daily.install",
        {login_user:node.login_user,public_key:key.public_key,key_id:key.id,fingerprint:key.fingerprint});
    }
    if(sub==="ssh-verification/start"&&req.method==="POST"){
      needRole(a,"admin");
      const rootKey=await env.DB.prepare(
        "SELECT public_key FROM node_ssh_proof_keys WHERE node_id=?"
      ).bind(node.id).first();
      ensure(rootKey,"NODE_PROOF_KEY_NOT_PINNED",409);
      const key=await env.DB.prepare(
        "SELECT id,fingerprint FROM public_keys WHERE purpose='daily' AND active=1"
      ).first<{id:string;fingerprint:string}>();
      ensure(key,"DAILY_KEY_MISSING",409);
      const installed=await env.DB.prepare(
        "SELECT public_key_id,login_user FROM node_keys WHERE node_id=? AND purpose='daily' AND state='installed' "+
        "ORDER BY rowid DESC LIMIT 1"
      ).bind(node.id).first<{public_key_id:string;login_user:string}>();
      const completed=await env.DB.prepare(
        "SELECT command_json FROM operations WHERE node_id=? AND action='ssh.daily.install' AND status='SUCCEEDED' "+
        "ORDER BY finished_at DESC LIMIT 1"
      ).bind(node.id).first<{command_json:string}>();
      let last:{expected_revision?:string;payload?:{key_id?:string;login_user?:string}}={};
      if(completed){
        try{last=JSON.parse(completed.command_json);}catch{throw new ApiError("INSTALL_RECORD_CORRUPT",409);}
      }
      const blocker=verificationBlocker({
        nodeOnline:isOnline(node),stage:node.init_stage,nodeRevision:node.config_revision,targetUser:node.login_user,
        activeKeyId:key.id,installedKeyId:installed?.public_key_id||"",installedKeyUser:installed?.login_user||"",
        lastInstallRevision:last.expected_revision||"",lastInstallKeyId:last.payload?.key_id||"",lastInstallUser:last.payload?.login_user||""
      });
      ensure(!blocker,blocker||"NOT_READY",409);
      const t=now();
      await env.DB.prepare(
        "UPDATE ssh_verifications SET status='EXPIRED' WHERE node_id=? AND status='PENDING' AND expires_at<=?"
      ).bind(node.id,t).run();
      const active=await env.DB.prepare(
        "SELECT id FROM ssh_verifications WHERE node_id=? AND status='PENDING' LIMIT 1"
      ).bind(node.id).first();
      ensure(!active,"VERIFICATION_ALREADY_PENDING",409);
      const token=base64url(crypto.getRandomValues(new Uint8Array(32)));
      const nonceHash=await sha256hex(token),id=crypto.randomUUID(),expires=t+VERIFICATION_TTL_SECONDS;
      ensure(env.COMMAND_PRIVATE_KEY,"SIGNER_NOT_CONFIGURED",503);
      const pendingOp=await env.DB.prepare(
        "SELECT id FROM operations WHERE node_id=? AND status IN ('CREATED','DISPATCHED','RUNNING') AND expires_at>? LIMIT 1"
      ).bind(node.id,t).first();
      ensure(!pendingOp,"NODE_OPERATION_IN_PROGRESS",409);
      const operationId=crypto.randomUUID();
      const cmd={
        v:1 as const,id:operationId,node_id:node.id,action:"ssh.verification.prepare" as const,
        actor:a.id,issued_at:t,expires_at:t+45,expected_revision:node.config_revision,
        payload:{
          verification_id:id,nonce_hash:nonceHash,login_user:node.login_user,
          fingerprint:key.fingerprint,key_id:key.id,config_revision:node.config_revision,
          issued_at:t,expires_at:expires
        }
      };
      const signed=await signCommand(cmd,env.COMMAND_PRIVATE_KEY);
      // These records commit together. A failed signed preparation cannot
      // leave a PENDING verification without an operation to dispatch.
      await env.DB.batch([
        env.DB.prepare(
          "INSERT INTO ssh_verifications(id,node_id,key_fingerprint,login_user,config_revision,nonce_hash,status,"+
          "created_at,expires_at,public_key_id,issued_by) VALUES (?,?,?,?,?,?,'PENDING',?,?,?,?)"
        ).bind(id,node.id,key.fingerprint,node.login_user,node.config_revision,nonceHash,t,expires,key.id,a.id),
        env.DB.prepare(
          "INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,expected_revision,command_json,signature,status,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(operationId,node.id,cmd.action,a.id,"verify-"+id,node.config_revision,signed.command,signed.signature,"CREATED",t,t+45)
      ]);
      await audit(env,a,node.id,"ssh.verification.start","PENDING",null,id);
      await dispatchPreparedOperation(env,node.id,operationId,signed);
      // No endpoint currently trusts a browser-issued 'verified' claim.
      // The nonce is returned once and NEVER stored as plaintext in D1.
      return response({verification_id:id,token,expires_at:expires,login_user:node.login_user,
        fingerprint:key.fingerprint,status:"PENDING",preparation:"QUEUED",preparation_operation_id:operationId, trusted_proof_available:false},201);
    }
    const verificationMatch=/^ssh-verification\/([0-9a-f-]{36})(?:\/cancel)?$/.exec(sub);
    if(verificationMatch){
      needRole(a,"admin");
      const verification=await env.DB.prepare(
        "SELECT id,node_id,login_user,key_fingerprint,config_revision,status,created_at,expires_at,verified_at,prepared_at,public_key_id "+
        "FROM ssh_verifications WHERE id=? AND node_id=?"
      ).bind(verificationMatch[1],node.id).first<any>();
      ensure(verification,"VERIFICATION_NOT_FOUND",404);
      if(verification.status==="PENDING"&&verification.expires_at<=now()){
        await env.DB.prepare("UPDATE ssh_verifications SET status='EXPIRED' WHERE id=? AND status='PENDING'").bind(verification.id).run();
        verification.status="EXPIRED";
      }
      if(sub.endsWith("/cancel")&&req.method==="POST"){
        ensure(verification.status==="PENDING","VERIFICATION_NOT_PENDING",409);
        await env.DB.prepare(
          "UPDATE ssh_verifications SET status='CANCELLED',invalidated_at=? WHERE id=? AND status='PENDING'"
        ).bind(now(),verification.id).run();
        await audit(env,a,node.id,"ssh.verification.cancel","CANCELLED",null,verification.id);
        return response({verification_id:verification.id,status:"CANCELLED"});
      }
      if(req.method==="GET"){
        const activeKey=await env.DB.prepare(
          "SELECT id FROM public_keys WHERE purpose='daily' AND active=1"
        ).first<{id:string}>();
        if(verification.status==="PENDING"&&
           (verification.config_revision!==node.config_revision||
            verification.public_key_id!==activeKey?.id)){
          await env.DB.prepare(
            "UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? WHERE id=? AND status='PENDING'"
          ).bind(now(),verification.id).run();
          verification.status="INVALIDATED";
        }
        // Never send nonce_hash or any credentials back from a read endpoint.
        return response({verification:{...verification,
          status:verificationStatus(verification.status,verification.expires_at,now())},
          trusted_proof_available:false});
      }
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
    const changes=[
      env.DB.prepare("UPDATE public_keys SET active=0 WHERE purpose=?").bind(purpose),
      env.DB.prepare("INSERT INTO public_keys(id,purpose,name,algorithm,public_key,fingerprint,version,active,created_by,created_at) VALUES (?,?,?,?,?,?,?,1,?,?)")
        .bind(id,purpose,name,key.algorithm,key.normalized,key.fingerprint,version,a.id,now())
    ];
    // Rotating the global daily key revokes any previously issued verification
    // challenge, without modifying keys on the actual VPS.
    if(purpose==="daily"){
      changes.push(env.DB.prepare(
        "UPDATE ssh_verifications SET status='INVALIDATED',invalidated_at=? WHERE status='PENDING'"
      ).bind(now()));
    }
    await env.DB.batch(changes);
    await audit(env,a,null,"keys."+purpose+".update","ok");
    return response({id,purpose,fingerprint:key.fingerprint,version,installed_nodes:0});
  }
  const opMatch=/^\/api\/v1\/operations\/([a-f0-9-]{36})$/.exec(p);
  if(opMatch&&req.method==="GET"){
    const op=await env.DB.prepare("SELECT id,node_id,action,status,result_code,detail,created_at,expires_at,finished_at FROM operations WHERE id=?").bind(opMatch[1]).first<any>();
    if(op?.status==="CREATED"&&op.expires_at<=now()){await env.DB.prepare("UPDATE operations SET status=\'EXPIRED\' WHERE id=? AND status=\'CREATED\'").bind(op.id).run();op.status="EXPIRED";}
    if(op?.status==="DISPATCHED"&&op.expires_at<=now())op.status="RESULT_UNKNOWN";
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

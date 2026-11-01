import {rotateGlobalPublicKey} from "./globalKeyRotation";
import {bootstrapFirstOwner,issueIdentityLinkToken,consumeIdentityLinkToken} from "./identityLinkStore";
import {createRemoteJWKSet,jwtVerify} from "jose";
import {parseNodeChanges,buildNodeSettingsUpdate,persistNodeSettingsUpdate} from "./nodeMetadata";
import {requirePinnedRootForDailyInstall} from "./dailyKeyProofPolicy";
import {persistRootProofPin} from "./rootProofPin";
import {projectOperationStatus,blockingNodeOperationCode,PENDING_NODE_OPERATION_SQL,withNodeOperationConflictGuard,assertNodeOperationSlotFree} from "./operationStatus";
import {dispatchPreparedOperation} from "./operationDispatch";
import {rotatePairingToken} from "./pairingTokenStore";
import {createNodeWithPairingToken} from "./nodeCreation";
import {persistVerificationStart,cancelPendingVerification,projectVerificationReadStatus} from "./verificationLifecycle";
import {findIdempotentOperation,recoverIdempotentInsertConflict} from "./operationIdempotency";
import {verificationBlocker,VERIFICATION_TTL_SECONDS} from "../../../packages/protocol/src/verification";
import {ApiError,errorResponse,response,now,safeHost,safeUser,validNodeId,parsePublicKey,sha256hex,base64url,decodeBase64url,signCommand} from "../../../packages/protocol/src/index";

interface Env {
  DB:D1Database; NODE_SESSIONS:DurableObjectNamespace; ASSETS:Fetcher;
  ACCESS_TEAM_DOMAIN:string; ACCESS_AUD:string; BOOTSTRAP_OWNER_EMAIL:string;
  COMMAND_PRIVATE_KEY:string;
  AGENT_HOSTNAME:string;
  MANUAL_SSH_ACTIONS_ENABLED?:string;
}
interface Actor {id:string; email:string; role:string; subject:string;}
const jsonLimit=8192;
const allowedMethods=new Set(["GET","POST","PUT","PATCH"]);
function ensure(condition:unknown,code:string,status=400):asserts condition {if(!condition)throw new ApiError(code,status);}
async function bodyJSON(req:Request):Promise<Record<string,unknown>> {
  const txt=await req.text();
  ensure(txt.length<=jsonLimit,"BODY_TOO_LARGE",413);
  let obj:unknown;try{obj=JSON.parse(txt);}catch{throw new ApiError("INVALID_JSON");}
  ensure(!!obj&&typeof obj==="object"&&!Array.isArray(obj),"INVALID_JSON");
  return obj as Record<string,unknown>;
}
interface AccessIdentity {subject:string;email:string;}
export async function verifyControlAccess(req:Request,env:Env):Promise<AccessIdentity>{
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
  const {subject,email}=await verifyControlAccess(req,env);
  let identity=await env.DB.prepare(
    "SELECT u.id,u.email,u.role,u.status FROM user_identities i JOIN users u ON i.user_id=u.id WHERE i.subject=?"
  ).bind(subject).first<{id:string;email:string;role:string;status:string}>();
  // First login bootstraps ONLY the first verified Access subject. Never
  // silently attach another identity provider because its email matches.
  if(!identity&&email===env.BOOTSTRAP_OWNER_EMAIL.toLowerCase()){
    const existing=await env.DB.prepare("SELECT id FROM users WHERE email=? LIMIT 1").bind(email).first();
    if(!existing){
      const id=crypto.randomUUID(),t=now();
      try {
        await bootstrapFirstOwner(env.DB,{
          userId:id,email,subject,createdAt:t,auditId:crypto.randomUUID()
        });
        identity={id,email,role:"owner",status:"active"};
      }catch(error){
        // A concurrent request with the SAME verified Access subject can
        // reuse its committed identity. Different subjects may never be
        // silently linked by email, even when both claim the Owner email.
        identity=await env.DB.prepare(
          "SELECT u.id,u.email,u.role,u.status FROM user_identities i "+
          "JOIN users u ON i.user_id=u.id WHERE i.subject=?"
        ).bind(subject).first<{id:string;email:string;role:string;status:string}>();
        if(!identity){
          const taken=await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();
          if(taken)throw new ApiError("FORBIDDEN",403);
          throw error;
        }
      }
    }
  }
  ensure(identity?.status==="active","FORBIDDEN",403);
  return {id:identity.id,email:identity.email,role:identity.role,subject};
}
async function claimIdentity(req:Request,env:Env):Promise<Response>{
  // Deliberately available to Access-verified users WITHOUT an SSH Manager
  // membership, but only with a one-time Owner-issued 256-bit linking token.
  const identity=await verifyControlAccess(req,env), b=await bodyJSON(req);
  const token=String(b.token||"");
  ensure(/^[a-zA-Z0-9_-]{40,64}$/.test(token),"INVALID_LINK_TOKEN",403);
  const tokenHash=await sha256hex(token),t=now();
  const row=await env.DB.prepare("SELECT t.id,t.user_id,u.email,u.status FROM identity_link_tokens t JOIN users u ON t.user_id=u.id WHERE t.token_hash=? AND t.used_at IS NULL AND t.expires_at>?")
    .bind(tokenHash,t).first<{id:string;user_id:string;email:string;status:string}>();
  ensure(row&&row.status==="active"&&row.email.toLowerCase()===identity.email,"INVALID_LINK_TOKEN",403);
  const bound=await env.DB.prepare("SELECT user_id FROM user_identities WHERE subject=?").bind(identity.subject).first();
  ensure(!bound,"IDENTITY_ALREADY_LINKED",409);
  // The identity binding, one-time token consumption and Owner audit
  // commit together. A conflicting subject never burns an unused token.
  await consumeIdentityLinkToken(env.DB,{
    subject:identity.subject,userId:row.user_id,email:identity.email,
    tokenId:row.id,tokenHash,claimedAt:t,auditId:crypto.randomUUID()
  });
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
  const hash=await sha256hex(token),t=now();
  await rotatePairingToken(env.DB,{
    nodeId,tokenId:crypto.randomUUID(),tokenHash:hash,expiresAt:t+600,
    createdBy:user.id,auditId:crypto.randomUUID(),createdAt:t
  });
  return {token,expires_in:600};
}

async function queueNodeOperation(
  req:Request, env:Env, a:Actor, node:any,
  action:"node.preflight"|"ssh.policy.inspect"|"ssh.daily.install"|"ssh.verification.prepare"|"ssh.password.disable"|"ssh.password.restore"|"ssh.config.rollback"|"ssh.rescue.enable"|"ssh.rescue.revoke", payload:Record<string,unknown>
):Promise<Response>{
  const idem=req.headers.get("Idempotency-Key");
  ensure(idem&&/^[a-zA-Z0-9_-]{12,100}$/.test(idem),"IDEMPOTENCY_KEY_REQUIRED");
  const existing=await findIdempotentOperation(env.DB,a.id,idem,{nodeId:node.id,action,payload},now());
  if(existing)return response(existing);
  ensure(isOnline(node),"NODE_OFFLINE",409);
  ensure(env.COMMAND_PRIVATE_KEY,"SIGNER_NOT_CONFIGURED",503);
  await assertNodeOperationSlotFree(env.DB,node.id,now());
  const id=crypto.randomUUID(),t=now();
  const cmd={v:1 as const,id,node_id:node.id,action,actor:a.id,issued_at:t,expires_at:t+45,expected_revision:node.config_revision,payload};
  const signed=await signCommand(cmd,env.COMMAND_PRIVATE_KEY);
  try{
  await withNodeOperationConflictGuard(()=>env.DB.batch([
    env.DB.prepare("INSERT INTO operations(id,node_id,action,operator_id,idempotency_key,expected_revision,command_json,signature,status,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
      .bind(id,node.id,action,a.id,idem,node.config_revision,signed.command,signed.signature,"CREATED",t,t+45),
    env.DB.prepare("INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) VALUES (?,?,?,?,?,'requested',?,?)")
      .bind(crypto.randomUUID(),a.id,node.id,action,id,
        typeof payload.reason==="string"?payload.reason.slice(0,280):null,t)
  ]),
    ()=>env.DB.prepare(PENDING_NODE_OPERATION_SQL).bind(node.id,now()).first<{status:string;expires_at:number}>(),now());
  }catch(error){
    const replay=await recoverIdempotentInsertConflict(error,()=>
      findIdempotentOperation(env.DB,a.id,idem,{nodeId:node.id,action,payload},now()));
    return response(replay);
  }
  await dispatchPreparedOperation(env,node.id,id,signed);
  return response({operation_id:id,status:"QUEUED"},202);
}

async function handle(req:Request,env:Env):Promise<Response>{
  const url=new URL(req.url);
  const p=url.pathname;
  if(p==="/api/v1/health")return response({status:"ok",version:"0.1.0",
    ssh_writes_enabled:env.MANUAL_SSH_ACTIONS_ENABLED==="true"});
  if(p==="/api/v1/identity/link-claim"&&req.method==="POST"){
    safeRequest(req);return claimIdentity(req,env);
  }
  const a=await actor(req,env);safeRequest(req);
  if(p==="/api/v1/identity/link-start"&&req.method==="POST"){
    needRole(a,"owner");
    const token=base64url(crypto.getRandomValues(new Uint8Array(32)));
    const digest=await sha256hex(token),t=now();
    await issueIdentityLinkToken(env.DB,{
      tokenId:crypto.randomUUID(),userId:a.id,tokenHash:digest,expiresAt:t+300,
      createdAt:t,auditId:crypto.randomUUID()
    });
    return response({token,expires_in:300});
  }
  if(p==="/api/v1/me"&&req.method==="GET")return response({
    id:a.id,email:a.email,role:a.role,agent_gateway_url:"https://"+env.AGENT_HOSTNAME,
    manual_ssh_actions_enabled:env.MANUAL_SSH_ACTIONS_ENABLED==="true"
  });
  if(p==="/api/v1/nodes"&&req.method==="GET"){
    const q=await env.DB.prepare("SELECT id,name,ssh_host,ssh_port,login_user,status,init_stage,config_revision,agent_version,os_id,last_seen_at,created_at,group_name,notes FROM nodes ORDER BY created_at DESC").all();
    return response({nodes:q.results});
  }
  if(p==="/api/v1/nodes"&&req.method==="POST"){
    needRole(a,"admin");const b=await bodyJSON(req);
    const name=String(b.name||"").trim(),host=String(b.ssh_host||"").trim(),login=String(b.login_user||"").trim();
    const port=Number(b.ssh_port||22);
    ensure(name.length>=1&&name.length<=80&&safeHost(host)&&safeUser(login)&&Number.isInteger(port)&&port>0&&port<65536,"INVALID_NODE");
    const id=crypto.randomUUID(),t=now();
    const token=base64url(crypto.getRandomValues(new Uint8Array(32)));
    const tokenHash=await sha256hex(token);
    await createNodeWithPairingToken(env.DB,{
      id,name,host,port,loginUser:login,createdAt:t,
      tokenId:crypto.randomUUID(),tokenHash,tokenExpiresAt:t+600,
      createdBy:a.id,auditId:crypto.randomUUID()
    });
    return response({node_id:id,token,expires_in:600},201);
  }
  const nodeMatch=/^\/api\/v1\/nodes\/([a-f0-9-]{36})(?:\/(.+))?$/.exec(p);
  if(nodeMatch){
    const node=await findNode(env,nodeMatch[1]),sub=nodeMatch[2]||"";
    if(!sub&&req.method==="GET")return response({node});
    if(!sub&&req.method==="PATCH"){
      needRole(a,"admin");
      const current={
        name:node.name,group_name:node.group_name||"",notes:node.notes||"",
        ssh_host:node.ssh_host,ssh_port:node.ssh_port,login_user:node.login_user,status:node.status
      };
      let changes;
      try{changes=parseNodeChanges(await bodyJSON(req),current);}
      catch(e){throw new ApiError(e instanceof Error?e.message:"INVALID_NODE_SETTINGS",400);}
      const update=buildNodeSettingsUpdate(node.id,current,changes);
      await persistNodeSettingsUpdate(env.DB,update,{
        auditId:crypto.randomUUID(),actorId:a.id,nodeId:node.id,createdAt:now()
      });
      return response({node:{...node,...changes}});
    }
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
      await persistRootProofPin(env.DB,{
        nodeId:node.id,publicKey,fingerprint,actorId:a.id,
        auditId:crypto.randomUUID(),createdAt:now()
      });
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
      // First pin the Root trust key on this exact VPS. The Agent cannot
      // register or replace it and must not act as its own SSH write proof.
      await requirePinnedRootForDailyInstall(env.DB,node.id);
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
      // A pending challenge is single-flight. Expired rows are transitioned
      // within persistVerificationStart's audited D1 batch, never before it.
      const active=await env.DB.prepare(
        "SELECT id FROM ssh_verifications WHERE node_id=? AND status='PENDING' AND expires_at>? LIMIT 1"
      ).bind(node.id,t).first();
      ensure(!active,"VERIFICATION_ALREADY_PENDING",409);
      const token=base64url(crypto.getRandomValues(new Uint8Array(32)));
      const nonceHash=await sha256hex(token),id=crypto.randomUUID(),expires=t+VERIFICATION_TTL_SECONDS;
      ensure(env.COMMAND_PRIVATE_KEY,"SIGNER_NOT_CONFIGURED",503);
      await assertNodeOperationSlotFree(env.DB,node.id,t);
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
      // Both the PENDING challenge and signed preparation operation must
      // survive with their attribution audit, or none of them is created.
      await withNodeOperationConflictGuard(
        ()=>persistVerificationStart(env.DB,{
          nodeId:node.id,verificationId:id,operationId,auditId:crypto.randomUUID(),
          operatorId:a.id,keyId:key.id,keyFingerprint:key.fingerprint,
          loginUser:node.login_user,configRevision:node.config_revision,
          nonceHash,createdAt:t,expiresAt:expires,operationExpiresAt:t+45,
          signedCommand:signed.command,signature:signed.signature
        }),
        ()=>env.DB.prepare(PENDING_NODE_OPERATION_SQL)
          .bind(node.id,now()).first<{status:string;expires_at:number}>(),
        now()
      );
      await dispatchPreparedOperation(env,node.id,operationId,signed);
      // No endpoint currently trusts a browser-issued 'verified' claim.
      // The nonce is returned once and NEVER stored as plaintext in D1.
      return response({verification_id:id,token,expires_at:expires,login_user:node.login_user,
        fingerprint:key.fingerprint,status:"PENDING",preparation:"QUEUED",preparation_operation_id:operationId, trusted_proof_available:false},201);
    }
    const verificationMatch=/^ssh-verification\\/([0-9a-f-]{36})(?:\\/cancel)?$/.exec(sub);
    if(verificationMatch){
      needRole(a,"admin");
      const verification=await env.DB.prepare(
        "SELECT id,node_id,login_user,key_fingerprint,config_revision,status,created_at,expires_at,verified_at,prepared_at,public_key_id "+
        "FROM ssh_verifications WHERE id=? AND node_id=?"
      ).bind(verificationMatch[1],node.id).first<any>();
      ensure(verification,"VERIFICATION_NOT_FOUND",404);
      if(sub.endsWith("/cancel")&&req.method==="POST"){
        // The predicate inside the D1 batch decides, not this stale read:
        // concurrent Root VERIFIED, expiry or prior cancellation -> HTTP 409.
        await cancelPendingVerification(env.DB,{
          nodeId:node.id,verificationId:verification.id,
          actorId:a.id,auditId:crypto.randomUUID(),at:now()
        });
        return response({verification_id:verification.id,status:"CANCELLED"});
      }
      if(req.method==="GET"){
        // Status projection is read-only: a GET must not perform an
        // unaudited expiry or invalidation, even if a proof is racing it.
        const activeKey=await env.DB.prepare(
          "SELECT id FROM public_keys WHERE purpose='daily' AND active=1"
        ).first<{id:string}>();
        const status=projectVerificationReadStatus(
          verification,now(),node.config_revision,activeKey?.id
        );
        return response({verification:{...verification,status},
          trusted_proof_available:status==="VERIFIED"});
      }
    }
    const manualActions:Record<string,
      "ssh.password.disable"|"ssh.password.restore"|"ssh.config.rollback"|"ssh.rescue.enable"|"ssh.rescue.revoke">={
      "ssh/password/disable":"ssh.password.disable",
      "ssh/password/restore":"ssh.password.restore",
      "ssh/config/rollback":"ssh.config.rollback",
      "rescue/enable":"ssh.rescue.enable",
      "rescue/revoke":"ssh.rescue.revoke"
    };
    if(req.method==="POST"&&Object.prototype.hasOwnProperty.call(manualActions,sub)){
      needRole(a,"owner");
      ensure(env.MANUAL_SSH_ACTIONS_ENABLED==="true","MANUAL_SSH_FEATURE_DISABLED",503);
      const b=await bodyJSON(req);
      const reason=String(b.reason||"");
      ensure(b.confirm_node_id===node.id&&reason.trim()===reason&&
        reason.length>=12&&reason.length<=280&&!/[\\x00-\\x1f\\x7f]/.test(reason),
        "MANUAL_NODE_CONFIRMATION_REQUIRED",403);
      const action=manualActions[sub];
      const proofKey=await env.DB.prepare(
        "SELECT node_id FROM node_ssh_proof_keys WHERE node_id=?"
      ).bind(node.id).first();
      ensure(proofKey,"NODE_ROOT_PROOF_KEY_NOT_PINNED",409);
      ensure(isOnline(node),"NODE_OFFLINE",409);
      ensure(/^[a-f0-9]{64}$/.test(node.config_revision),"POLICY_INSPECTION_REQUIRED",409);
      const payload:Record<string,unknown>={
        confirm_node_id:node.id,login_user:node.login_user,reason
      };
      if(action==="ssh.password.disable"){
        ensure(node.init_stage==="KEY_VERIFIED","FRESH_VERIFIED_DAILY_LOGIN_REQUIRED",409);
        const latest=await env.DB.prepare(
          "SELECT v.id,v.proof_id,v.verified_at FROM ssh_verifications v "+
          "JOIN public_keys k ON k.id=v.public_key_id AND k.purpose='daily' AND k.active=1 "+
          "JOIN node_keys nk ON nk.node_id=v.node_id AND nk.public_key_id=k.id "+
          "AND nk.login_user=v.login_user AND nk.purpose='daily' AND nk.state='installed' "+
          "AND nk.verified_at IS NOT NULL "+
          "WHERE v.node_id=? AND v.login_user=? AND v.config_revision=? "+
          "AND v.status='VERIFIED' AND v.proof_id IS NOT NULL AND v.verified_at>? "+
          "ORDER BY v.verified_at DESC LIMIT 1"
        ).bind(node.id,node.login_user,node.config_revision,now()-1800)
          .first<{id:string;proof_id:string;verified_at:number}>();
        ensure(latest,"FRESH_VERIFIED_DAILY_LOGIN_REQUIRED",409);
        payload.verification_id=latest.id;
        payload.proof_id=latest.proof_id;
      }else if(action==="ssh.password.restore"||action==="ssh.config.rollback"){
        ensure(node.init_stage==="PASSWORD_DISABLED","PASSWORD_POLICY_NOT_MANAGED",409);
        const snapshot=await env.DB.prepare(
          "SELECT id,local_ref,revision FROM ssh_config_snapshots "+
          "WHERE node_id=? AND restored_at IS NULL ORDER BY created_at DESC LIMIT 1"
        ).bind(node.id).first<{id:string;local_ref:string;revision:string}>();
        ensure(snapshot&&snapshot.revision===node.config_revision,"CONFIG_SNAPSHOT_STALE",409);
        ensure(b.snapshot_ref===snapshot.local_ref,"MANUAL_SNAPSHOT_CONFIRMATION_REQUIRED",403);
        payload.snapshot_ref=snapshot.local_ref;
      }else if(action==="ssh.rescue.enable"){
        const existing=await env.DB.prepare(
          "SELECT id FROM node_keys WHERE node_id=? AND purpose='rescue' AND state='installed' LIMIT 1"
        ).bind(node.id).first();
        ensure(!existing,"RESCUE_KEY_ALREADY_ACTIVE_ON_NODE",409);
        const key=await env.DB.prepare(
          "SELECT id,public_key,fingerprint FROM public_keys WHERE purpose='rescue' AND active=1"
        ).first<{id:string;public_key:string;fingerprint:string}>();
        ensure(key,"RESCUE_PUBLIC_KEY_MISSING",409);
        payload.key_id=key.id;payload.public_key=key.public_key;payload.fingerprint=key.fingerprint;
      }else if(action==="ssh.rescue.revoke"){
        const installed=await env.DB.prepare(
          "SELECT nk.public_key_id AS id,k.public_key,k.fingerprint FROM node_keys nk "+
          "JOIN public_keys k ON k.id=nk.public_key_id "+
          "WHERE nk.node_id=? AND nk.purpose='rescue' AND nk.state='installed' LIMIT 1"
        ).bind(node.id).first<{id:string;public_key:string;fingerprint:string}>();
        ensure(installed,"RESCUE_KEY_NOT_ACTIVE_ON_NODE",409);
        payload.key_id=installed.id;
        payload.public_key=installed.public_key;
        payload.fingerprint=installed.fingerprint;
      }
      return queueNodeOperation(req,env,a,node,action,payload);
    }
    if(sub==="rescue/state"&&req.method==="GET"){
      needRole(a,"admin");
      const installed=await env.DB.prepare(
        "SELECT nk.id,nk.public_key_id,nk.login_user,k.fingerprint,k.version "+
        "FROM node_keys nk JOIN public_keys k ON k.id=nk.public_key_id "+
        "WHERE nk.node_id=? AND nk.purpose='rescue' AND nk.state='installed' LIMIT 1"
      ).bind(node.id).first();
      return response({active:!!installed,installed:installed||null});
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
    const purpose=keyMatch[1] as "daily"|"rescue";
    const id=crypto.randomUUID(),name=String(b.name||purpose).slice(0,80);
    const version=await rotateGlobalPublicKey(env.DB,{
      id,purpose,name,algorithm:key.algorithm,publicKey:key.normalized,
      fingerprint:key.fingerprint,actorId:a.id,auditId:crypto.randomUUID(),createdAt:now()
    });
    return response({id,purpose,fingerprint:key.fingerprint,version,installed_nodes:0});
  }
  if(p==="/api/v1/operations"&&req.method==="GET"){
    const nodeId=url.searchParams.get("node_id");
    if(nodeId)ensure(validNodeId(nodeId),"INVALID_NODE_ID",400);
    const q=nodeId?
      await env.DB.prepare("SELECT id,node_id,action,status,result_code,detail,created_at,expires_at,finished_at FROM operations WHERE node_id=? ORDER BY created_at DESC LIMIT 100").bind(nodeId).all():
      await env.DB.prepare("SELECT id,node_id,action,status,result_code,detail,created_at,expires_at,finished_at FROM operations ORDER BY created_at DESC LIMIT 100").all();
    const at=now();
    return response({operations:q.results.map((op:any)=>({
      ...op,status:projectOperationStatus(op,at)
    }))});
  }
  const opMatch=/^\/api\/v1\/operations\/([a-f0-9-]{36})$/.exec(p);
  if(opMatch&&req.method==="GET"){
    const op=await env.DB.prepare("SELECT id,node_id,action,status,result_code,detail,created_at,expires_at,finished_at FROM operations WHERE id=?").bind(opMatch[1]).first<any>();
    ensure(op,"OPERATION_NOT_FOUND",404);
    const effectiveStatus=projectOperationStatus(op,now());
    if(op.status==="CREATED"&&effectiveStatus==="EXPIRED")
      await env.DB.prepare("UPDATE operations SET status='EXPIRED' WHERE id=? AND status='CREATED'").bind(op.id).run();
    return response({operation:{...op,status:effectiveStatus}});
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

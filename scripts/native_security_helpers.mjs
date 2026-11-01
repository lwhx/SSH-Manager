// Safety checks for single-Worker Cloudflare Builds and explicit empty-Staging recovery.
export const SIGNER_RECOVERY_FLAG = "CONFIRM_EMPTY_STAGING_SIGNER_REPAIR";

export function validateEmptyStagingQuery(payload) {
  const required = ["nodes","operations","paired_agents","pairing_tokens","device_nonces","node_keys","verifications","snapshots"];
  if(!Array.isArray(payload)||payload.length!==1||payload[0]?.success!==true||
    !Array.isArray(payload[0]?.results)||payload[0].results.length!==1){
    throw Error("D1 returned an incomplete or unsuccessful read-only verification response");
  }
  const row=payload[0].results[0];
  for(const key of required){
    if(!Object.hasOwn(row,key)||!Number.isSafeInteger(row[key])||row[key]!==0){
      throw Error("Staging signer recovery blocked: "+key+" is not confirmed empty");
    }
  }
  return true;
}
export const EMPTY_STAGING_SQL=[
  "SELECT",
  "(SELECT COUNT(*) FROM nodes) AS nodes,",
  "(SELECT COUNT(*) FROM operations) AS operations,",
  "(SELECT COUNT(*) FROM agent_credentials) AS paired_agents,",
  "(SELECT COUNT(*) FROM pairing_tokens) AS pairing_tokens,",
  "(SELECT COUNT(*) FROM device_nonces) AS device_nonces,",
  "(SELECT COUNT(*) FROM node_keys) AS node_keys,",
  "(SELECT COUNT(*) FROM ssh_verifications) AS verifications,",
  "(SELECT COUNT(*) FROM ssh_config_snapshots) AS snapshots"
].join(" ");

export function verifyWorkerTargets(settings,{publicKey,databaseId,requireSigner=false}){
  if(!Array.isArray(settings?.bindings)){
    throw Error("Actual Cloudflare Worker is missing or has no bindings");
  }
  const get=name=>{
    const a=settings.bindings.filter(x=>x?.name===name);
    if(a.length!==1)throw Error("Actual Worker is missing or duplicates "+name);
    return a[0];
  };
  const pub=get("COMMAND_PUBLIC_KEY"),db=get("DB"),ssh=get("MANUAL_SSH_ACTIONS_ENABLED");
  const sessions=get("NODE_SESSIONS");
  if(pub.type!=="plain_text"||pub.text!==publicKey||
    db.type!=="d1"||String(db.database_id||db.id||"").toLowerCase()!==databaseId.toLowerCase()||
    ssh.type!=="plain_text"||ssh.text!=="false"||
    sessions.type!=="durable_object_namespace"||sessions.class_name!=="NodeSession"||sessions.script_name){
    throw Error("Actual Worker has mismatched D1, public signer, DO or SSH write safety configuration");
  }
  if(requireSigner&&get("COMMAND_PRIVATE_KEY").type!=="secret_text"){
    throw Error("Actual Worker private signer is not a Cloudflare secret");
  }
  return true;
}


// Recreate a DELETED Staging Worker while retaining its existing D1.
// Only unpaired WAITING_PAIR nodes and owner/audit metadata may remain.
// Never permit recovery with device credentials, verified SSH or operations.
export const DELETED_WORKER_RECOVERY_FLAG="CONFIRM_UNPAIRED_STAGING_WORKER_RECREATE";
export const DELETED_WORKER_RECOVERY_SQL=[
 "SELECT",
 "(SELECT COUNT(*) FROM nodes) AS total_nodes,",
 "(SELECT COUNT(*) FROM nodes WHERE status!='unpaired' OR init_stage!='WAITING_PAIR') AS non_unpaired_nodes,",
 "(SELECT COUNT(*) FROM agent_credentials) AS paired_agents,",
 "(SELECT COUNT(*) FROM pairing_tokens WHERE used_at IS NOT NULL) AS used_pair_tokens,",
 "(SELECT COUNT(*) FROM pairing_tokens WHERE used_at IS NULL AND expires_at>unixepoch()) AS active_pair_tokens,",
 "(SELECT COUNT(*) FROM device_nonces) AS device_nonces,",
 "(SELECT COUNT(*) FROM operations) AS operations,",
 "(SELECT COUNT(*) FROM node_keys) AS node_keys,",
 "(SELECT COUNT(*) FROM ssh_verifications) AS verifications,",
 "(SELECT COUNT(*) FROM ssh_config_snapshots) AS snapshots,",
 "(SELECT COUNT(*) FROM node_ssh_proof_keys) AS proof_keys"
].join(" ");
export function validateDeletedWorkerStagingQuery(payload){
 const one=Array.isArray(payload)&&payload.length===1&&payload[0];
 const row=one?.success===true&&Array.isArray(one.results)&&one.results.length===1?one.results[0]:null;
 if(!row||typeof row!=="object")throw Error("Deleted-Worker D1 verification failed or returned incomplete results");
 if(!Number.isSafeInteger(row.total_nodes)||row.total_nodes<0)
  throw Error("Deleted-Worker D1 node count cannot be verified");
 const zero=["non_unpaired_nodes","paired_agents","used_pair_tokens",
  "active_pair_tokens","device_nonces","operations","node_keys",
  "verifications","snapshots","proof_keys"];
 for(const key of zero){
  if(!Object.hasOwn(row,key)||!Number.isSafeInteger(row[key])||row[key]!==0)
   throw Error("Deleted-Worker recovery blocked by nonempty/unknown "+key);
 }
 return {totalNodes:row.total_nodes};
}


// Read-only migration gate for an EXISTING Staging D1. The 0008 partial
// unique index cannot be applied if historical unresolved operations overlap.
// A non-empty, untrusted or malformed response always blocks deployment.
export const UNRESOLVED_OPERATION_PREFLIGHT_SQL=[
 "SELECT node_id, COUNT(*) AS unresolved_count",
 "FROM operations",
 "WHERE status IN ('CREATED','DISPATCHED','RUNNING')",
 "GROUP BY node_id",
 "HAVING COUNT(*) > 1",
 "LIMIT 1"
].join(" ");
export function validateUnresolvedOperationPreflight(payload){
 if(!Array.isArray(payload)||payload.length!==1||
    payload[0]?.success!==true||!Array.isArray(payload[0]?.results)){
  throw Error("Staging D1 operation preflight failed: incomplete or invalid read-only query");
 }
 if(payload[0].results.length!==0){
  throw Error(
   "Staging D1 operation preflight blocked: multiple unresolved operations on a VPS. "+
   "Inspect the existing D1 and VPS manually; NEVER auto-delete or overwrite command history."
  );
 }
 return true;
}

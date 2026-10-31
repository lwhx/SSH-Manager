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

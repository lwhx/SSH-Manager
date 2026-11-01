import {ApiError,safeHost,safeUser} from "../../../packages/protocol/src/index";
export type NodeSettingsData={
 name:string;group_name:string;notes:string;ssh_host:string;ssh_port:number;login_user:string;status:string;
};
export function parseNodeChanges(input:Record<string,unknown>,current:NodeSettingsData):Omit<NodeSettingsData,"status"> {
 const allowed=new Set(["name","group_name","notes","ssh_host","ssh_port","login_user"]);
 if(!Object.keys(input).length||Object.keys(input).some(k=>!allowed.has(k)))throw Error("INVALID_NODE_SETTINGS");
 const name=String(input.name??current.name).trim();
 const group_name=String(input.group_name??current.group_name??"").trim();
 const notes=String(input.notes??current.notes??"").trim();
 const ssh_host=String(input.ssh_host??current.ssh_host).trim();
 const ssh_port=Number(input.ssh_port??current.ssh_port);
 const login_user=String(input.login_user??current.login_user).trim();
 if(!name||name.length>80||group_name.length>80||notes.length>2000||
    [name,group_name,notes].some(x=>/[\x00-\x1f\x7f]/.test(x))||
    !safeHost(ssh_host)||!safeUser(login_user)||
    !Number.isInteger(ssh_port)||ssh_port<1||ssh_port>65535)throw Error("INVALID_NODE_SETTINGS");
 if(current.status!=="unpaired"&&
    (ssh_host!==current.ssh_host||ssh_port!==current.ssh_port||login_user!==current.login_user))
   throw Error("PAIRED_NODE_CONNECTION_LOCKED");
 return {name,group_name,notes,ssh_host,ssh_port,login_user};
}

/**
 * Optimistic, single-row update: a node that becomes paired (or is edited by
 * another administrator) between SELECT and PATCH can never be redirected.
 * Active Agent credentials are a second guard in case status is stale.
 */
export function buildNodeSettingsUpdate(
 nodeId:string,current:NodeSettingsData,changed:Omit<NodeSettingsData,"status">
):{sql:string;args:(string|number)[]} {
 const connectionChanged=
  changed.ssh_host!==current.ssh_host||
  changed.ssh_port!==current.ssh_port||
  changed.login_user!==current.login_user;
 const sql=
  "UPDATE nodes SET name=?,group_name=?,notes=?,ssh_host=?,ssh_port=?,login_user=? "+
  "WHERE id=? AND status=? AND name=? AND group_name=? AND notes=? AND ssh_host=? AND ssh_port=? AND login_user=?"+
  (connectionChanged?
   " AND NOT EXISTS (SELECT 1 FROM agent_credentials WHERE node_id=? AND revoked_at IS NULL)":"");
 const args:(string|number)[]=[
  changed.name,changed.group_name,changed.notes,changed.ssh_host,changed.ssh_port,changed.login_user,
  nodeId,current.status,current.name,current.group_name,current.notes,current.ssh_host,current.ssh_port,current.login_user
 ];
 if(connectionChanged)args.push(nodeId);
 return {sql,args};
}

export interface NodeSettingsAudit {
 auditId:string;actorId:string;nodeId:string;createdAt:number;
}
/**
 * Persist the optimistic node update and its audit event in one D1 transaction.
 * If the audit insert fails, D1 rolls back the metadata update as well.
 */
export async function persistNodeSettingsUpdate(
 db:D1Database,update:{sql:string;args:(string|number)[]},audit:NodeSettingsAudit
):Promise<void>{
 const [changed,logged]=await db.batch([
  db.prepare(update.sql).bind(...update.args),
  db.prepare(
   "INSERT INTO audit_logs(id,actor_id,node_id,action,operation_id,result,reason,created_at) "+
   "SELECT ?,?,?, 'node.settings.update',NULL,'ok',NULL,? WHERE changes()=1"
  ).bind(audit.auditId,audit.actorId,audit.nodeId,audit.createdAt)
 ]);
 if(changed.meta.changes!==1)throw new ApiError("NODE_SETTINGS_CONFLICT",409);
 if(logged.meta.changes!==1)throw new ApiError("NODE_SETTINGS_AUDIT_FAILED",500);
}

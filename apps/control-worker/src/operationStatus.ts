import {ApiError} from "../../../packages/protocol/src/index";
export interface OperationRow {status:string;expires_at:number}
export function projectOperationStatus(op:OperationRow,at:number):string {
 if(op.expires_at<=at){
  if(op.status==="CREATED")return "EXPIRED";
  if(op.status==="DISPATCHED"||op.status==="RUNNING")return "RESULT_UNKNOWN";
 }
 return op.status;
}
export function blockingNodeOperationCode(op:OperationRow,at:number):string|null{
 const effective=projectOperationStatus(op,at);
 if(effective==="RESULT_UNKNOWN")return "NODE_OPERATION_RESULT_UNKNOWN";
 if(effective==="CREATED"||effective==="DISPATCHED"||effective==="RUNNING")return "NODE_OPERATION_IN_PROGRESS";
 return null;
}
// Expiry is not proof that a dispatched SSH command did not run.
// The Agent may have applied a command before the result was lost.
export const PENDING_NODE_OPERATION_SQL=
 "SELECT id,status,expires_at FROM operations WHERE node_id=? AND "+
 "(status IN ('DISPATCHED','RUNNING') OR (status='CREATED' AND expires_at>?)) "+
 "ORDER BY created_at ASC LIMIT 1";


/**
 * D1's partial unique index provides single-flight safety even when two
 * authorized requests race after the pre-insert SELECT. The losing request
 * receives an explicit 409; it must never retry the INSERT/dispatch.
 */
function isNodeOperationUniqueConflict(error:unknown):boolean {
 const target=/UNIQUE constraint failed:\s*(?:operations\.node_id\b|idx_one_unresolved_operation_per_node\b)/i;
 let current:unknown=error;
 for(let depth=0;depth<4;depth++){
  if(typeof current==="string")return target.test(current);
  if(!(current instanceof Error))return false;
  if(target.test(current.message))return true;
  current=current.cause;
 }
 return false;
}
export async function withNodeOperationConflictGuard<T>(
 attempt:()=>Promise<T>,
 lookup:()=>Promise<OperationRow|null>,
 at:number
):Promise<T> {
 try{return await attempt();}
 catch(error){
  if(!isNodeOperationUniqueConflict(error))throw error;
  // The conflicting operation's status determines whether its result is
  // unknown. A lookup failure retains the original D1 error; never
  // indicate a successful enqueue.
  let pending:OperationRow|null;
  try{pending=await lookup();}catch{throw error;}
  const code=pending?blockingNodeOperationCode(pending,at):null;
  throw new ApiError(code||"NODE_OPERATION_IN_PROGRESS",409);
 }
}


/**
 * CREATED is not dispatched until the gateway atomically claims it.
 * Expiring only stale CREATED operations releases the D1 single-flight
 * index safely. DISPATCHED/RUNNING outcomes must remain blocking forever
 * until an authenticated terminal report resolves them.
 *
 * Both normal actions and verification preparation must use this guard.
 */
export async function assertNodeOperationSlotFree(
 db:D1Database,nodeId:string,at:number
):Promise<void>{
 await db.prepare(
  "UPDATE operations SET status='EXPIRED' WHERE node_id=? AND status='CREATED' AND expires_at<=?"
 ).bind(nodeId,at).run();
 const pending=await db.prepare(PENDING_NODE_OPERATION_SQL)
  .bind(nodeId,at).first<OperationRow>();
 const blocking=pending?blockingNodeOperationCode(pending,at):null;
 if(blocking)throw new ApiError(blocking,409);
}

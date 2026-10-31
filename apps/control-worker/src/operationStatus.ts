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

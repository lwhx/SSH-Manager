import {ApiError} from "../../../packages/protocol/src/index";
import {projectOperationStatus} from "./operationStatus";

export interface RequestedOperationIntent {
 nodeId:string;
 action:string;
 payload:Record<string,unknown>;
}
interface ExistingOperation {
 id:string;node_id:string;action:string;status:string;expires_at:number;command_json:string;
}

function record(value:unknown):value is Record<string,unknown> {
 return value!==null&&typeof value==="object"&&!Array.isArray(value);
}

// Idempotency means the same node, action and exact JSON payload; object
// property order does not change the request's meaning.
function stableJson(value:unknown):string {
 return JSON.stringify(value,(_key,part)=>{
  if(!record(part))return part;
  return Object.fromEntries(Object.entries(part).sort(([a],[b])=>a<b?-1:a>b?1:0));
 });
}

/**
 * A reused Idempotency-Key must never return a foreign VPS operation ID or
 * silently accept a different SSH payload. A legitimate retry returns the
 * original result, even when the Agent went offline in the meantime.
 */
export async function findIdempotentOperation(
 db:D1Database,operatorId:string,idempotencyKey:string,
 intent:RequestedOperationIntent,at:number
):Promise<{operation_id:string;status:string}|null>{
 const old=await db.prepare(
  "SELECT id,node_id,action,status,expires_at,command_json "+
  "FROM operations WHERE operator_id=? AND idempotency_key=?"
 ).bind(operatorId,idempotencyKey).first<ExistingOperation>();
 if(!old)return null;

 let command:unknown;
 try{command=JSON.parse(old.command_json);}
 catch{throw new ApiError("IDEMPOTENCY_SCOPE_CONFLICT",409);}
 if(!record(command)||!record(command.payload)||
    old.node_id!==intent.nodeId||old.action!==intent.action||
    command.node_id!==intent.nodeId||command.action!==intent.action||
    stableJson(command.payload)!==stableJson(intent.payload)){
  throw new ApiError("IDEMPOTENCY_SCOPE_CONFLICT",409);
 }
 return {operation_id:old.id,status:projectOperationStatus(old,at)};
}

interface DispatchEnvironment{
 DB:D1Database;
 NODE_SESSIONS:DurableObjectNamespace;
}
/**
 * A failed HTTP ACK is NOT proof that a WebSocket command failed to reach
 * the Agent. Never put an ambiguously delivered SSH command back into the
 * HTTPS poll queue. It must remain DISPATCHED until a signed terminal report.
 */
export async function dispatchPreparedOperation(
 env:DispatchEnvironment,nodeId:string,operationId:string,
 signed:{command:string;signature:string}
):Promise<void>{
 const claimed=await env.DB.prepare(
  "UPDATE operations SET status='DISPATCHED' WHERE id=? AND status='CREATED'"
 ).bind(operationId).run();
 if(claimed.meta.changes!==1)return;
 try{
  const stub=env.NODE_SESSIONS.get(env.NODE_SESSIONS.idFromName(nodeId));
  const reply=await stub.fetch("https://node.internal/dispatch",{
   method:"POST",body:JSON.stringify(signed)
  });
  if(!reply.ok)return;
  const result=await reply.json() as {delivered?:unknown};
  if(result&&result.delivered===0){
   // An explicit, trusted zero-delivery response is the only safe condition
   // in which HTTPS polling can take over this command.
   await env.DB.prepare(
    "UPDATE operations SET status='CREATED' WHERE id=? AND status='DISPATCHED'"
   ).bind(operationId).run();
  }
 }catch{
  // The Durable Object may have delivered the signed command before the
  // connection failed. Fail closed; do not dispatch this operation again.
 }
}

import control, {verifyControlAccess} from "../../control-worker/src/index";
import agent from "../../agent-gateway/src/index";
import {errorResponse} from "../../../packages/protocol/src/index";
import {classifyHostPath} from "./router";

// The Durable Object now lives in this SAME Worker (no service binding).
export {NodeSession} from "../../agent-gateway/src/index";

interface Env{
 DB:D1Database;
 NODE_SESSIONS:DurableObjectNamespace;
 ASSETS:Fetcher;
 CONTROL_HOSTNAME:string;
 AGENT_HOSTNAME:string;
 ACCESS_TEAM_DOMAIN:string;
 ACCESS_AUD:string;
 BOOTSTRAP_OWNER_EMAIL:string;
 COMMAND_PRIVATE_KEY:string;
 COMMAND_PUBLIC_KEY:string;
 MANUAL_SSH_ACTIONS_ENABLED?:string;
}
const reject=(status:number,code:string)=>new Response(JSON.stringify({error:code}),{
 status,headers:{"Content-Type":"application/json; charset=utf-8",
  "Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}
});

export default {
 async fetch(req:Request,env:Env):Promise<Response>{
  const url=new URL(req.url);
  const area=classifyHostPath(
   url.hostname,url.pathname,env.CONTROL_HOSTNAME,env.AGENT_HOSTNAME
  );
  if(area==="misconfigured")return reject(503,"ROUTING_NOT_CONFIGURED");
  if(area==="deny")return reject(404,"NOT_FOUND");
  if(area==="agent"){
   // Existing signature authentication, nonce replay prevention, and
   // root signed proofs remain inside the Agent Gateway handlers.
   return agent.fetch(req,env);
  }
  // Even if Cloudflare Access was accidentally removed at the edge, ALL
  // admin HTML/static assets and API paths are denied without a valid
  // Cloudflare Access JWT. The header is cryptographically verified.
  try{
   await verifyControlAccess(req,env);
  }catch(err){
   return errorResponse(err);
  }
  return control.fetch(req,env);
 }
};

export type HostArea="control"|"agent"|"deny"|"misconfigured";

// Exact hostname matching prevents anonymous Agent traffic from reaching the
// management API or static assets via the unprotected Agent custom domain.
export function classifyHostPath(
 host:string,path:string,configuredControl:string,configuredAgent:string
):HostArea{
 const c=String(configuredControl||"").toLowerCase();
 const a=String(configuredAgent||"").toLowerCase();
 const valid=(value:string)=>value.length>=4&&value.length<=253&&
  value.includes(".")&&!value.includes("..")&&
  /^[a-z0-9.-]+$/.test(value)&&
  !value.startsWith(".")&&!value.endsWith(".")&&
  value.split(".").every(x=>x.length>=1&&x.length<=63&&!x.startsWith("-")&&!x.endsWith("-"));
 if(!valid(c)||!valid(a)||c===a)return "misconfigured";
 if(host===c){
  if(path==="/agent"||path.startsWith("/agent/"))return "deny";
  return "control";
 }
 if(host===a){
  // No admin API, SPA, static file, /health for Control, or arbitrary path
  // may be served from the Agent hostname.
  return path.startsWith("/agent/v1/")?"agent":"deny";
 }
 return "deny";
}

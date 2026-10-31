export const ALLOWED_AGENT_ACTIONS = [
  "node.preflight","node.status","ssh.policy.inspect","ssh.verification.prepare","ssh.daily.install",
  "ssh.password.disable","ssh.password.restore","ssh.config.rollback","ssh.rescue.enable","ssh.rescue.revoke"
] as const;
export type AgentAction = typeof ALLOWED_AGENT_ACTIONS[number];
export interface Command {
  v: 1; id: string; node_id: string; action: AgentAction; actor: string;
  issued_at: number; expires_at: number; expected_revision: string;
  payload: Record<string,unknown>;
}
export interface SignedCommand { command: string; signature: string; }
export const now = () => Math.floor(Date.now()/1000);
export function response(value: unknown, status=200): Response {
  return new Response(JSON.stringify(value), {status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
}
export class ApiError extends Error {
  constructor(public code:string,public httpStatus=400){super(code);}
}
export function errorResponse(e:unknown):Response {
  if(e instanceof ApiError)return response({error:e.code},e.httpStatus);
  console.error("request failed",e instanceof Error?e.message:"unknown error");
  return response({error:"INTERNAL_ERROR"},500);
}
export function validNodeId(s:string):boolean{return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s);}
export function safeHost(s:string):boolean{return /^(?=.{1,253}$)[A-Za-z0-9.:\-[\]]+$/.test(s)&&!s.includes("..");}
export function safeUser(s:string):boolean{return /^[a-z_][a-z0-9_-]{0,31}\$?$/.test(s);}
export function base64url(data:Uint8Array):string {
 let b="";for(const byte of data)b+=String.fromCharCode(byte);
 return btoa(b).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
export function decodeBase64url(s:string):Uint8Array {
 const raw=atob(s.replace(/-/g,"+").replace(/_/g,"/"));return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
export async function sha256hex(input:string):Promise<string>{
 const h=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(input)));
 return [...h].map(x=>x.toString(16).padStart(2,"0")).join("");
}
export async function sha256urlBytes(input:Uint8Array):Promise<string>{
 const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",Uint8Array.from(input)));
 let b="";for(const byte of digest)b+=String.fromCharCode(byte);
 // OpenSSH fingerprints use STANDARD unpadded base64, not base64url.
 return btoa(b).replace(/=+$/,"");
}
export async function parsePublicKey(value:string):Promise<{algorithm:string;normalized:string;fingerprint:string}>{
 const parts=value.trim().split(/\s+/);
 if(parts[0]!=="ssh-ed25519"||!parts[1]||parts[1].length>1024)throw new ApiError("KEY_INVALID");
 let bin:Uint8Array;
 try{bin=Uint8Array.from(atob(parts[1]),c=>c.charCodeAt(0));}catch{throw new ApiError("KEY_INVALID");}
 const view=new DataView(bin.buffer,bin.byteOffset,bin.byteLength);
 if(bin.length!==51||view.getUint32(0)!==11||new TextDecoder().decode(bin.slice(4,15))!=="ssh-ed25519"||view.getUint32(15)!==32)throw new ApiError("KEY_INVALID");
 const comment=parts.slice(2).join(" ").slice(0,80).replace(/[\r\n]/g,"");
 return {algorithm:"ssh-ed25519",normalized:"ssh-ed25519 "+parts[1]+(comment?" "+comment:""),fingerprint:"SHA256:"+await sha256urlBytes(bin)};
}
export async function signCommand(command:Command,base64pkcs8:string):Promise<SignedCommand>{
 const raw=Uint8Array.from(atob(base64pkcs8),c=>c.charCodeAt(0));
 const key=await crypto.subtle.importKey("pkcs8",raw,{name:"Ed25519"},false,["sign"]);
 const serialized=JSON.stringify(command);
 const signature=base64url(new Uint8Array(await crypto.subtle.sign("Ed25519",key,new TextEncoder().encode(serialized))));
 return {command:serialized,signature};
}

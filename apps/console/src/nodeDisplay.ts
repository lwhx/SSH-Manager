export interface DirectoryNode {
 id:string;name:string;ssh_host:string;login_user:string;status:string;init_stage:string;
 last_seen_at?:number|null;group_name?:string|null;created_at?:number|null;
}
export function isNodeOnline(node:Pick<DirectoryNode,"status"|"last_seen_at">,now=Date.now()/1000):boolean {
 return node.status==="online"&&Number(node.last_seen_at)>now-90;
}
export type DirectoryOptions={search?:string;status?:string;group?:string;sort?:"name"|"recent"};
export function filterNodes<T extends DirectoryNode>(nodes:T[],options:DirectoryOptions={},now=Date.now()/1000):T[]{
 const query=(options.search||"").trim().toLocaleLowerCase();
 return nodes.filter(node=>{
  const state=node.status==="unpaired"?"unpaired":isNodeOnline(node,now)?"online":"offline";
  if(options.status&&options.status!=="all"&&state!==options.status)return false;
  if(options.group&&options.group!=="all"&&(node.group_name||"")!==options.group)return false;
  return !query||[node.name,node.ssh_host,node.login_user,node.group_name||""].some(v=>v.toLocaleLowerCase().includes(query));
 }).sort((a,b)=>options.sort==="name"?
  a.name.localeCompare(b.name,"zh-CN")||a.id.localeCompare(b.id):
  Number(b.created_at||0)-Number(a.created_at||0)||a.id.localeCompare(b.id));
}

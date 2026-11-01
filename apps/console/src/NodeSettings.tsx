import React,{useEffect,useState,type FormEvent} from "react";

export interface EditableNode {
 id:string;name:string;group_name?:string|null;notes?:string|null;
 ssh_host:string;ssh_port:number;login_user:string;status:string;
}
export interface NodeSettingsInput {
 name:string;group_name:string;notes:string;ssh_host:string;ssh_port:number;login_user:string;
}
interface Props {node:EditableNode;canEdit:boolean;onSave:(data:NodeSettingsInput)=>Promise<void>;}
function toInput(node:EditableNode):NodeSettingsInput{
 return {name:node.name,group_name:node.group_name||"",notes:node.notes||"",
  ssh_host:node.ssh_host,ssh_port:node.ssh_port,login_user:node.login_user};
}
export default function NodeSettings({node,canEdit,onSave}:Props){
 const [form,setForm]=useState<NodeSettingsInput>(()=>toInput(node));
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const [saved,setSaved]=useState(false);
 useEffect(()=>{setForm(toInput(node));setError("");setSaved(false);},
  [node.id,node.name,node.group_name,node.notes,node.ssh_host,node.ssh_port,node.login_user]);
 const connectionEditable=canEdit&&node.status==="unpaired";
 async function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();
  if(!canEdit||busy)return;
  setBusy(true);setError("");setSaved(false);
  try{await onSave(form);setSaved(true);}
  catch(e){setError(e instanceof Error?e.message:String(e));}
  finally{setBusy(false);}
 }
 return <form className="node-settings-form" onSubmit={e=>void submit(e)}>
  <p>显示资料可随时调整。为了保护已建立的 Agent 身份与 SSH 验证链，已配对 VPS 的主机、端口、用户不可修改。</p>
  <div className="settings-fields">
   <label>节点名称<input name="name" required maxLength={80} disabled={!canEdit||busy} value={form.name}
     onChange={e=>setForm(p=>({...p,name:e.target.value}))}/></label>
   <label>分组<input name="group_name" maxLength={80} disabled={!canEdit||busy} value={form.group_name}
     onChange={e=>setForm(p=>({...p,group_name:e.target.value}))}/></label>
   <label className="full-width">备注<textarea name="notes" maxLength={2000} rows={4} disabled={!canEdit||busy} value={form.notes}
     onChange={e=>setForm(p=>({...p,notes:e.target.value}))}/></label>
   <label>SSH 主机 / IP<input name="ssh_host" disabled={!connectionEditable||busy} required value={form.ssh_host}
     onChange={e=>setForm(p=>({...p,ssh_host:e.target.value}))}/></label>
   <label>SSH 端口<input name="ssh_port" type="number" min={1} max={65535} disabled={!connectionEditable||busy} required value={form.ssh_port}
     onChange={e=>setForm(p=>({...p,ssh_port:Number(e.target.value)}))}/></label>
   <label>登录用户<input name="login_user" disabled={!connectionEditable||busy} required value={form.login_user}
     onChange={e=>setForm(p=>({...p,login_user:e.target.value}))}/></label>
  </div>
  {!connectionEditable&&<p className="hint">连接参数已锁定。请勿为更改 SSH 主机而复用或重配对现有节点身份。</p>}
  {canEdit&&<button type="submit" disabled={busy||!form.name.trim()||!form.ssh_host.trim()||!form.login_user.trim()}>
   {busy?"正在保存…":"保存当前 VPS 设置"}
  </button>}
  {error&&<p className="safety-locked" role="alert">{error}</p>}
  {saved&&<p role="status">保存成功，操作已记录审计。</p>}
 </form>;
}

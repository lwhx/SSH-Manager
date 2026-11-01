import React,{useEffect,useRef,useState,type FormEvent} from "react";
import AgentInstallWizard from "./AgentInstallWizard";
import {isNodeOnline} from "./nodeDisplay";

export interface NewNodeDraft{name:string;ssh_host:string;ssh_port:number;login_user:string;}
export interface WizardNode{id:string;name:string;status:string;init_stage:string;last_seen_at?:number;}
export interface WizardPair{node_id:string;token:string;expires_at:number;}
interface Props{
 open:boolean;busy:boolean;gateway:string;revision:string;
 onClose:()=>void;
 onCreate:(draft:NewNodeDraft)=>Promise<{node:WizardNode;pair:WizardPair|null}>;
 onNewToken:(node:WizardNode)=>Promise<WizardPair>;
 onRefresh:(id:string)=>Promise<WizardNode>;
 onOpenNode:(id:string)=>void;
}
export default function AddNodeWizard({
 open,busy,gateway,revision,onClose,onCreate,onNewToken,onRefresh,onOpenNode
}:Props){
 const [step,setStep]=useState<1|2|3>(1);
 const [draft,setDraft]=useState<NewNodeDraft>({name:"",ssh_host:"",ssh_port:22,login_user:"root"});
 const [created,setCreated]=useState<WizardNode|null>(null);
 const [pair,setPair]=useState<WizardPair|null>(null);
 const [working,setWorking]=useState(false);
 const [error,setError]=useState("");
 const closeButton=useRef<HTMLButtonElement>(null);
 useEffect(()=>{
  if(!open)return;
  const previouslyFocused=document.activeElement as HTMLElement|null;
  closeButton.current?.focus();
  const onKey=(e:KeyboardEvent)=>{if(e.key==="Escape"&&!busy&&!working)onClose();};
  document.addEventListener("keydown",onKey);
  return()=>{document.removeEventListener("keydown",onKey);previouslyFocused?.focus();};
 },[open,busy,working,onClose]);
 if(!open)return null;
 async function submit(e:FormEvent<HTMLFormElement>){
  e.preventDefault();
  if(working||busy)return;
  setWorking(true);setError("");
  try{
   const r=await onCreate(draft);
   setCreated(r.node);setPair(r.pair);setStep(2);
  }catch(e){setError(e instanceof Error?e.message:String(e));}
  finally{setWorking(false);}
 }
 async function newToken(){
  if(!created||working)return;
  setWorking(true);setError("");
  try{setPair(await onNewToken(created));}
  catch(e){setError(e instanceof Error?e.message:String(e));}
  finally{setWorking(false);}
 }
 async function refresh(){
  if(!created||working)return;
  setWorking(true);setError("");
  try{
   const node=await onRefresh(created.id);
   setCreated(node);
   if(node.status!=="unpaired")setStep(3);
  }catch(e){setError(e instanceof Error?e.message:String(e));}
  finally{setWorking(false);}
 }
 return <div className="wizard-backdrop"><section className="card wizard-card" role="dialog" aria-modal="true" aria-labelledby="wizard-title">
  <div className="directory-header"><div><h2 id="wizard-title">添加 VPS</h2><p>逐台添加，不触碰已有 SSH 登录配置</p></div>
   <button type="button" ref={closeButton} className="secondary" disabled={working||busy} onClick={onClose}>关闭 ×</button>
  </div>
  <div className="wizard-steps" aria-label="创建 VPS 步骤">
   {(["基本信息","安装 Agent","确认连接"] as const).map((name,i)=><span key={name} className={step===i+1?"active":step>i+1?"done":""}>{i+1}. {name}</span>)}
  </div>
  {step===1&&<form onSubmit={e=>void submit(e)}>
   <label>节点名称<input required maxLength={80} autoFocus value={draft.name} onChange={e=>setDraft(v=>({...v,name:e.target.value}))} placeholder="例如：香港 · 生产节点"/></label>
   <label>IP 或域名<input required value={draft.ssh_host} onChange={e=>setDraft(v=>({...v,ssh_host:e.target.value}))} placeholder="198.51.100.1"/></label>
   <div className="settings-fields"><label>SSH 用户<input required value={draft.login_user} onChange={e=>setDraft(v=>({...v,login_user:e.target.value}))}/></label>
   <label>SSH 端口<input required type="number" min={1} max={65535} value={draft.ssh_port} onChange={e=>setDraft(v=>({...v,ssh_port:Number(e.target.value)}))}/></label></div>
   <p className="hint">创建节点只写入面板数据库，不会自动连接 VPS，也不会修改 sshd。</p>
   <button type="submit" disabled={working||busy||!draft.name.trim()||!draft.ssh_host.trim()||!draft.login_user.trim()}>创建节点并继续 →</button>
  </form>}
  {step===2&&created&&<>
   <AgentInstallWizard node={created} pair={pair} gateway={gateway} revision={revision}
    busy={working||busy} canPair={true} onNewToken={()=>void newToken()} onRefresh={()=>void refresh()}/>
   <div className="wizard-actions"><button className="secondary" onClick={()=>onOpenNode(created.id)}>转到节点详情</button>
    <button disabled={working||busy} onClick={()=>{setStep(3);void refresh();}}>检查连接状态 →</button></div>
  </>}
  {step===3&&created&&<div className="wizard-result">
   <h3>{isNodeOnline(created)?"Agent 已上线":created.status==="unpaired"?"等待 Agent 配对":"Agent 已配对，等待上线"}</h3>
   <p>节点：{created.name}</p>
   <p>初始化阶段：{created.init_stage}</p>
   <p>只有 Agent 心跳上线、Root Helper 的可信证据和真实 SSH 公钥登录验证完成后，才能由管理员手工关闭密码登录。</p>
   <div className="wizard-actions"><button className="secondary" disabled={working||busy} onClick={()=>void refresh()}>重新检查</button>
    {created.status==="unpaired"&&<button className="secondary" onClick={()=>setStep(2)}>返回配对</button>}
    <button onClick={()=>onOpenNode(created.id)}>打开此 VPS →</button></div>
  </div>}
  {error&&<p className="safety-locked" role="alert">{error}</p>}
 </section></div>;
}

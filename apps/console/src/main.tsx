import React,{useEffect,useState} from "react";
import{createRoot}from"react-dom/client";
import "./style.css";
import ManualOperations from "./ManualOperations";
import AgentInstallWizard from "./AgentInstallWizard";
import NodeDirectory from "./NodeDirectory";
import AddNodeWizard,{type NewNodeDraft,type WizardNode,type WizardPair} from "./AddNodeWizard";
import NodeSettings,{type NodeSettingsInput} from "./NodeSettings";
import TaskCenter from "./TaskCenter";
import {parseConsoleRoute,consoleRouteHref,consoleNodeTabHref,parseNodeDetailTab,type ConsolePage,type NodeDetailTab} from "./nodeNavigation";
import {isNodeOnline} from "./nodeDisplay";
type NodeInfo={id:string;name:string;ssh_host:string;ssh_port:number;login_user:string;status:string;init_stage:string;last_seen_at?:number;config_revision:string;group_name?:string;notes?:string;created_at?:number;agent_version?:string;os_id?:string};
type MeInfo={email:string;role:string;manual_ssh_actions_enabled:boolean;agent_gateway_url:string};
type PairInfo={node_id:string;token:string;expires_at:number};
type KeyInfo={id:string;purpose:string;fingerprint:string;public_key:string;version:number;name:string};
type VerificationInfo={id:string;status:string;expires_at:number;fingerprint:string;login_user:string;token?:string;prepared_at?:number|null};
async function api<T>(path:string,method="GET",data?:unknown,headers?:Record<string,string>):Promise<T>{
 const res=await fetch("/api/v1"+path,{method,headers:{"Content-Type":"application/json",...headers},body:data?JSON.stringify(data):undefined,credentials:"same-origin"});
 const result:any=await res.json();
 if(!res.ok)throw new Error(result.error||"REQUEST_FAILED");return result;
}
function App(){
 const [me,setMe]=useState<MeInfo|null>(null);
 const [nodes,setNodes]=useState<NodeInfo[]>([]);
 const [keys,setKeys]=useState<KeyInfo[]>([]);
 const [route,setRoute]=useState(()=>parseConsoleRoute(window.location.hash));
 const page=route.page;
 const selected=nodes.find(node=>node.id===route.nodeId)||null;
 const detailTab=parseNodeDetailTab(window.location.hash);
 const [createOpen,setCreateOpen]=useState(false);
 const [message,setMessage]=useState("");
 const [pair,setPair]=useState<PairInfo|null>(null);
 const [keyInput,setKeyInput]=useState({daily:"",rescue:""});
 const [audit,setAudit]=useState<any[]>([]);
 const [operation,setOperation]=useState<string|null>(null);
 const [verification,setVerification]=useState<VerificationInfo|null>(null);
 const [proofPublicInput,setProofPublicInput]=useState("");
 const [proofFingerprintInput,setProofFingerprintInput]=useState("");
 const [pinnedRootProof,setPinnedRootProof]=useState<{fingerprint:string}|null>(null);
 const [linkToken,setLinkToken]=useState("");
 const [linkInput,setLinkInput]=useState("");
 const [operationState,setOperationState]=useState<{status:string;result_code?:string;detail?:string}|null>(null);
 const [busy,setBusy]=useState(false);
 const owner=me?.role==="owner";
 function navigate(next:ConsolePage,nodeId?:string|null,tab:NodeDetailTab="overview"){
  const href=next==="nodes"&&nodeId?consoleNodeTabHref(nodeId,tab):consoleRouteHref(next,nodeId);
  window.location.hash=href;
  setRoute(parseConsoleRoute(href));
  setCreateOpen(false);
 }
 function alertError(e:unknown){setMessage(e instanceof Error?e.message:String(e));}
 async function refresh(){
  try{
   const u=await api<MeInfo>("/me");setMe(u);
   const n=await api<{nodes:NodeInfo[]}>("/nodes");setNodes(n.nodes);
     if(u.role!=="viewer"){const k=await api<{keys:KeyInfo[]}>("/keys");setKeys(k.keys);}
  }catch(e){alertError(e);}
 }
 useEffect(()=>{void refresh();},[]);
 useEffect(()=>{
  const sync=()=>setRoute(parseConsoleRoute(window.location.hash));
  window.addEventListener("hashchange",sync);
  return()=>window.removeEventListener("hashchange",sync);
 },[]);
 useEffect(()=>{
  setVerification(null);setOperation(null);setOperationState(null);
  setPinnedRootProof(null);setProofPublicInput("");setProofFingerprintInput("");
  setPair(old=>old?.node_id===route.nodeId?old:null);
 },[route.nodeId]);
 useEffect(()=>{if(page==="audit"&&owner)void loadAudit();},[page,owner]);
 useEffect(()=>{
  if(!selected||!me||me.role==="viewer"){setPinnedRootProof(null);return;}
  let live=true;
  void api<{pinned:{fingerprint:string}|null}>("/nodes/"+selected.id+"/ssh-proof-key")
   .then(v=>{if(live)setPinnedRootProof(v.pinned)})
   .catch(e=>{if(live)alertError(e)});
  return()=>{live=false};
 },[selected?.id,me?.role]);

 useEffect(()=>{
  if(!selected||!verification||verification.status!=="PENDING")return;
  let running=true;
  const update=async()=>{
   try{
    const reply=await api<{verification:{id:string;status:string;expires_at:number;prepared_at?:number|null}}>(
      "/nodes/"+selected.id+"/ssh-verification/"+verification.id);
    if(running)setVerification(previous=>previous&&previous.id===reply.verification.id?
      {...previous,status:reply.verification.status,expires_at:reply.verification.expires_at,prepared_at:reply.verification.prepared_at}:previous);
   }catch(e){if(running)alertError(e);}
  };
  void update();
  const timer=setInterval(()=>void update(),3000);
  return()=>{running=false;clearInterval(timer);};
 },[selected?.id,verification?.id,verification?.status]);

 useEffect(()=>{
  if(operationState?.status==="SUCCEEDED")void refresh();
 },[operation,operationState?.status]);
 useEffect(()=>{
  if(!operation)return;
  let active=true;
  const check=async()=>{
   try{
    const r=await api<{operation:{status:string;result_code?:string;detail?:string}}>("/operations/"+operation);
    if(active)setOperationState(r.operation);
   }catch(e){if(active)alertError(e);}
  };
  void check();
  const interval=setInterval(()=>void check(),2500);
  return ()=>{active=false;clearInterval(interval);};
 },[operation]);
 async function act(cb:()=>Promise<void>){setBusy(true);setMessage("");try{await cb();await refresh();}catch(e){alertError(e);}finally{setBusy(false);}}
 async function createLink(){
  await act(async()=>{
   const result=await api<{token:string}>("/identity/link-start","POST",{});
   setLinkToken(result.token);
   setMessage("绑定码仅显示在当前会话，5分钟后过期。请在另一种 Cloudflare Access 登录方式下使用。");
  });
 }
 async function claimLink(){
  await act(async()=>{
   await api("/identity/link-claim","POST",{token:linkInput});
   setLinkInput("");
   setMessage("身份绑定成功。");
  });
 }
 async function createNodeFromWizard(draft:NewNodeDraft):Promise<{node:NodeInfo;pair:WizardPair}>{
  const result=await api<{node_id:string;token:string;expires_in:number}>("/nodes","POST",draft);
  const created:NodeInfo={id:result.node_id,...draft,status:"unpaired",init_stage:"WAITING_PAIR",config_revision:"unverified"};
  const ticket={node_id:result.node_id,token:result.token,expires_at:Date.now()+result.expires_in*1000};
  setPair(ticket);
  setNodes(previous=>[created,...previous.filter(node=>node.id!==created.id)]);
  return {node:created,pair:ticket};
 }
 async function newWizardToken(node:WizardNode):Promise<WizardPair>{
  const value=await api<{token:string;expires_in:number}>("/nodes/"+node.id+"/pairing-token","POST",{});
  const ticket={node_id:node.id,token:value.token,expires_at:Date.now()+value.expires_in*1000};
  setPair(ticket);
  return ticket;
 }
 async function refreshWizardNode(id:string):Promise<NodeInfo>{
  const reply=await api<{node:NodeInfo}>("/nodes/"+id);
  setNodes(previous=>previous.map(n=>n.id===id?reply.node:n));
  return reply.node;
 }
 async function saveNodeSettings(data:NodeSettingsInput):Promise<void>{
  if(!selected)throw Error("NODE_NOT_FOUND");
  await api("/nodes/"+selected.id,"PATCH",data);
  await refresh();
 }
 async function refreshPairToken(node:NodeInfo){await act(async()=>{
  if(node.status!=="unpaired")throw Error("NODE_ALREADY_PAIRED");
  const r=await api<{token:string;expires_in:number}>("/nodes/"+node.id+"/pairing-token","POST",{});
  setPair({node_id:node.id,token:r.token,expires_at:Date.now()+r.expires_in*1000});
  setMessage("当前节点生成了新的 10 分钟配对令牌，旧令牌已失效。");
 });}
 async function saveKey(kind:"daily"|"rescue"){await act(async()=>{const k=await api<{fingerprint:string}>("/keys/"+kind,"PUT",{public_key:keyInput[kind],name:kind});setKeyInput(v=>({...v,[kind]:""}));setMessage("公钥已保存："+k.fingerprint+"。保存不会在 VPS 上启用救援公钥。");});}
 async function preflight(node:NodeInfo){
  await act(async()=>{
   const result=await api<{operation_id:string}>("/nodes/"+node.id+"/preflight","POST",{},{"Idempotency-Key":crypto.randomUUID()});
   setOperation(result.operation_id);setOperationState(null);
   setMessage("只读诊断任务已创建；执行结果会单独显示。");
  });
 }
 async function inspectPolicy(node:NodeInfo){
  await act(async()=>{
   const result=await api<{operation_id:string}>("/nodes/"+node.id+"/ssh-policy/inspect","POST",{},{"Idempotency-Key":crypto.randomUUID()});
   setOperation(result.operation_id);setOperationState(null);
   setMessage("已请求检查 sshd 最终生效配置。Agent 必须连接独立 Root Helper 才能完成。");
  });
 }
 async function pinRootProof(node:NodeInfo){
  if(!confirm("只绑定 "+node.name+" 的 Root Helper 证明公钥？请先通过 VPS 控制台独立核对公钥和指纹。"))return;
  await act(async()=>{
   const result=await api<{fingerprint:string}>("/nodes/"+node.id+"/ssh-proof-key","POST",{
    public_key:proofPublicInput.trim(),confirm_node_id:node.id,
    confirm_fingerprint:proofFingerprintInput.trim()
   });
   setPinnedRootProof({fingerprint:result.fingerprint});
   setProofPublicInput("");setProofFingerprintInput("");
   setMessage("仅为本台 VPS 固定 Root Helper 证明公钥："+result.fingerprint+"。绑定不会修改 SSH 登录方式。");
  });
 }
 async function beginVerification(node:NodeInfo){
  await act(async()=>{
   const result=await api<{
    verification_id:string;token:string;expires_at:number;
    login_user:string;fingerprint:string;status:string;trusted_proof_available:boolean;preparation_operation_id:string;
   }>("/nodes/"+node.id+"/ssh-verification/start","POST",{});
   setVerification({id:result.verification_id,status:result.status,expires_at:result.expires_at,
     login_user:result.login_user,fingerprint:result.fingerprint,token:result.token,prepared_at:null});
   setOperation(result.preparation_operation_id);setOperationState(null);
   setMessage("挑战已签发，正在请求当前 VPS 的 Root Helper 本地准备；这不代表 SSH 登录验证成功。");
  });
 }
 async function cancelVerification(node:NodeInfo){
  if(!verification)return;
  await act(async()=>{
   await api("/nodes/"+node.id+"/ssh-verification/"+verification.id+"/cancel","POST",{});
   setVerification(previous=>previous?{...previous,status:"CANCELLED"}:null);
   setMessage("验证挑战已撤销；SSH 配置未被修改。");
  });
 }
 async function installDaily(node:NodeInfo){
  if(!confirm("仅对 "+node.name+"（"+node.login_user+"）部署日常公钥？不关闭密码登录。"))return;
  await act(async()=>{const result=await api<{operation_id:string}>("/nodes/"+node.id+"/daily-key/install","POST",{},{"Idempotency-Key":crypto.randomUUID()});setOperation(result.operation_id);setOperationState(null);setMessage("已请求安装；需要等待 Agent 回报，不代表已经安装成功。");});
 }
 async function loadAudit(){
  try{setAudit((await api<{entries:any[]}>("/audit")).entries);}
  catch(e){alertError(e);}
 }
 const nav=[["dashboard","仪表盘"],["nodes","VPS 节点"],["keys","双公钥管理"],["tasks","任务中心"],["audit","操作审计"],["settings","系统设置"]] as const;
 return <div className="layout"><aside className="sidebar"><h2>🛡️ SSH Manager</h2><small>Cloudflare · Agent 安全管理</small><nav>{nav.filter(([id])=>id!=="audit"||owner).map(([id,title])=><button key={id} className={page===id?"active":""} onClick={()=>navigate(id)}>{title}</button>)}</nav><div className="account">{me?me.email+" · "+me.role:"等待 Cloudflare Access 验证"}</div></aside><main className="main">
 <header><div><h1>{page==="dashboard"?"安全总览":page==="nodes"?"VPS 节点管理":page==="keys"?"SSH 公钥管理":page==="tasks"?"任务中心":page==="settings"?"系统设置":"操作审计"}</h1><p>危险 SSH 修改只能逐台人工确认，经 Root Helper 独立签名回执验收，永不自动回滚。</p></div><button className="secondary" onClick={()=>void refresh()}>刷新数据</button></header>
 {message&&<div className="notice" role="status">{message}<button onClick={()=>setMessage("")}>×</button></div>}
 {!me&&<section className="card"><h3>等待 SSH Manager 授权</h3><p>请先通过 Cloudflare Access 使用 GitHub 或 Cloudflare 账户认证。如果这是第二个身份提供方，需要 Owner 从已授权会话生成一次性绑定码。</p><label>5 分钟身份绑定码<input value={linkInput} onChange={e=>setLinkInput(e.target.value)} placeholder="粘贴已授权 Owner 提供的绑定码"/></label><button disabled={busy||!linkInput.trim()} onClick={()=>void claimLink()}>验证并绑定另一登录身份</button></section>}
 {me&&page==="dashboard"&&<><div className="stats"><section className="card"><small>节点总数</small><strong>{nodes.length}</strong></section><section className="card"><small>Agent 在线</small><strong>{nodes.filter(n=>n.status==="online"&&(n.last_seen_at||0)>Date.now()/1000-90).length}</strong></section><section className="card"><small>待验证节点</small><strong>{nodes.filter(n=>n.init_stage!=="COMPLETE").length}</strong></section></div><section className="card"><h3>安全边界</h3><p>日常公钥初始化与可信 SSH 验证是正式关闭密码登录的前置条件。紧急救援公钥仅可由管理员在单台 VPS 上手动启用。当前基础版本不允许任何自动回滚。</p><button onClick={()=>navigate("nodes")}>进入节点管理</button></section></>}
 {me&&page==="nodes"&&<div className="nodes-page">
 {route.nodeId&&!selected?<section className="card">
  <h3>未找到该 VPS</h3><p>节点可能不存在，或当前用户没有权限访问。</p>
  <button className="secondary" onClick={()=>navigate("nodes")}>返回服务器列表</button>
 </section>:!selected?<div>
  <div className="stats"><section className="card"><small>节点总数</small><strong>{nodes.length}</strong></section>
   <section className="card"><small>Agent 在线</small><strong>{nodes.filter(n=>isNodeOnline(n)).length}</strong></section>
   <section className="card"><small>尚未配对</small><strong>{nodes.filter(n=>n.status==="unpaired").length}</strong></section></div>
  <NodeDirectory nodes={nodes} canCreate={me.role!=="viewer"} onCreate={()=>setCreateOpen(true)}
   onSelect={node=>navigate("nodes",node.id)}/>
  {me.role!=="viewer"&&createOpen&&<AddNodeWizard open={true} busy={busy} gateway={me.agent_gateway_url||""}
   revision={String(import.meta.env.VITE_SSH_MANAGER_COMMIT||"")}
   onClose={()=>setCreateOpen(false)} onCreate={createNodeFromWizard} onNewToken={newWizardToken}
   onRefresh={refreshWizardNode} onOpenNode={id=>navigate("nodes",id,"agent")}/>}
 </div>:<div>
  <div className="node-detail-toolbar"><button className="secondary" onClick={()=>navigate("nodes")}>← 服务器列表</button><span> / {selected.name}</span></div>
  <section className="card node-summary"><div><h2>{selected.name}</h2><p>{selected.ssh_host}:{selected.ssh_port} · {selected.login_user} · {selected.group_name||"未分组"}</p></div>
   <span className={isNodeOnline(selected)?"connected":"disconnected"}>{isNodeOnline(selected)?"● Agent 在线":"○ Agent 未在线"}</span>
  </section>
  <div className="node-tabs" role="tablist" aria-label="VPS 管理页签">
   {([["overview","概览"],["agent","Agent 管理"],["ssh","SSH 安全"],["history","操作记录"],["settings","节点设置"]] as const).map(([id,label])=>
    <button key={id} type="button" role="tab" aria-selected={detailTab===id} className={detailTab===id?"active":"secondary"}
     onClick={()=>navigate("nodes",selected.id,id)}>{label}</button>)}
  </div>
  {detailTab==="overview"&&<section className="card">
   <h3>节点概览</h3><div className="overview-grid">
    <div className="hint"><small>Agent 状态</small><strong>{isNodeOnline(selected)?"在线":selected.status==="unpaired"?"未配对":"离线"}</strong><small>{selected.agent_version||"Agent 尚无版本信息"}</small></div>
    <div className="hint"><small>SSH 初始化阶段</small><strong>{selected.init_stage}</strong><small>不会自动关闭密码认证</small></div>
    <div className="hint"><small>当前配置版本</small><code>{selected.config_revision}</code></div>
    <div className="hint"><small>最后心跳</small><strong>{selected.last_seen_at?new Date(selected.last_seen_at*1000).toLocaleString():"暂无记录"}</strong></div>
   </div><p>先在「Agent 管理」完成配对，再在「SSH 安全」逐步检查与验证；人工危险操作需要独立确认。</p>
   <button className="secondary" onClick={()=>navigate("nodes",selected.id,selected.status==="unpaired"?"agent":"ssh")}>前往下一步 →</button>
  </section>}
  {detailTab==="agent"&&<section className="card"><h3>Agent 安装、配对与连接</h3>
 <AgentInstallWizard key={selected.id} node={selected} pair={pair}
    gateway={me.agent_gateway_url||""}
    revision={String(import.meta.env.VITE_SSH_MANAGER_COMMIT||"")}
    busy={busy} canPair={me.role!=="viewer"}
    onNewToken={()=>void refreshPairToken(selected)}
    onRefresh={()=>void refresh()}/>

  </section>}
  {detailTab==="ssh"&&<section className="card"><h3>本 VPS 的 SSH 安全</h3>
 <button disabled={busy||selected.status!=="online"} onClick={()=>void preflight(selected)}>执行 SSH 只读环境检查</button><button disabled={busy||selected.status!=="online"} onClick={()=>void inspectPolicy(selected)}>检查 SSH 实际生效配置（Helper）</button><button disabled={busy||selected.status!=="online"||selected.config_revision==="unverified"||!keys.some(k=>k.purpose==="daily")} onClick={()=>void installDaily(selected)}>部署日常公钥（不关闭密码）</button><hr/><h4>本台 VPS 的可信 Root Helper</h4>
 {pinnedRootProof?<p>已绑定本机证明密钥指纹：<code>{pinnedRootProof.fingerprint}</code>（不可由 Agent 直接更换）</p>:
 <div className="hint"><p>Root Helper 证明公钥尚未绑定。先在该 VPS 本机手动生成并核对签名公钥，再由 Owner 绑定到本节点。</p>
 {owner&&<>
  <label>Root Helper 公钥（base64url 格式）<input value={proofPublicInput} onChange={e=>setProofPublicInput(e.target.value)} placeholder="从 VPS 本机复制 43 字符公钥"/></label>
  <label>本机输出的 SHA256 指纹（须单独确认）<input value={proofFingerprintInput} onChange={e=>setProofFingerprintInput(e.target.value)} placeholder="SHA256:..."/></label>
  <button disabled={busy||!proofPublicInput.trim()||!proofFingerprintInput.trim()} onClick={()=>void pinRootProof(selected)}>确认并固定本 VPS 证明公钥</button>
 </>}
 </div>}
 <hr/><h4>SSH 日常密钥登录验证</h4><p>先安装日常公钥，再为当前节点生成一次性挑战。<strong>挑战不代表验证成功</strong>：服务器侧认证证据链已经实现，但尚未完成真实 VPS + Cloudflare Staging 全链路验收。</p>
 <button disabled={busy||selected.status!=="online"||selected.init_stage!=="WAITING_VERIFICATION"||!pinnedRootProof||(verification?.status==="PENDING")}
  onClick={()=>void beginVerification(selected)}>生成单节点验证挑战（5分钟）</button>
 {verification&&<div className="hint">
  <strong>验证任务：{verification.status}</strong>
  <p>VPS 本机挑战准备：{verification.prepared_at?"已确认准备完成":"尚未收到成功回执"}</p>
  <p>对应用户：{verification.login_user}</p>
  <p>目标公钥：{verification.fingerprint}</p>
  <p>到期：{new Date(verification.expires_at*1000).toLocaleString()}</p>
  {verification.token&&verification.status==="PENDING"&&<><p>一次性挑战（只在首次显示）：</p><code>{verification.token}</code></>}
  <p>{verification.status==="VERIFIED"?"控制端已接受当前节点的 Root Helper 签名认证证明。仍不自动关闭密码登录。":"只有经本机真实公钥认证、可信证明并通过 Cloudflare 验签，才会进入 VERIFIED。不要凭手工点击认定成功。"}</p>
  {verification.status==="PENDING"&&<button className="secondary" disabled={busy}
    onClick={()=>void cancelVerification(selected)}>撤销本次挑战</button>}
 </div>}
 <ManualOperations key={selected.id} node={selected} owner={owner} enabled={!!me.manual_ssh_actions_enabled}
    rescueKeyAvailable={keys.some(k=>k.purpose==="rescue")}
    onOperation={id=>{setOperation(id);setOperationState(null);}}/>{operation&&<div className="hint"><p>任务 ID：{operation}</p><p>实际状态：{operationState?.status||"等待 Agent"} · {operationState?.result_code||""}</p>{operationState?.detail&&<pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{operationState.detail}</pre>}<small>配置检查不能代替可信 SSH 登录验证；安装日常公钥不会关闭密码登录。</small></div>}
  </section>}
  {detailTab==="history"&&<TaskCenter nodes={nodes} nodeId={selected.id} onOpenNode={id=>navigate("nodes",id)}/>}
  {detailTab==="settings"&&<section className="card"><h3>节点设置</h3>
   <NodeSettings key={selected.id} node={selected} canEdit={me.role!=="viewer"} onSave={saveNodeSettings}/>
  </section>}
 </div>}</div>}
 {me&&page==="tasks"&&<TaskCenter nodes={nodes} onOpenNode={id=>navigate("nodes",id)}/>}
 {me&&page==="settings"&&<section className="card">
  <h3>平台设置</h3><p>登录由 Cloudflare Access 承担，支持已授权的 GitHub 或 Cloudflare 身份；面板本身没有密码登录。</p>
  <div className="overview-grid">
   <div className="hint"><small>Agent 网关</small><strong>{me.agent_gateway_url}</strong></div>
   <div className="hint"><small>人工高危操作</small><strong>{me.manual_ssh_actions_enabled?"已允许（需单台确认）":"已关闭"}</strong></div>
  </div>
  <p>日常和救援公钥只保存在配置中，保存不会自动安装到任何 VPS。所有部署、手动回滚及救援变更必须进入对应节点执行。</p>
  <button className="secondary" onClick={()=>navigate("keys")}>管理双公钥 →</button>
 </section>}
 {me&&page==="keys"&&<div className="columns">{(["daily","rescue"] as const).map(kind=>{const k=keys.find(k=>k.purpose===kind);return <section className="card" key={kind}><h3>{kind==="daily"?"🔑 日常公钥":"🛟 救援公钥"}</h3><p>{kind==="daily"?"只在单节点初始化时授权安装。":"默认不对任何 VPS 生效；保存公钥不会下发救援授权。"}</p>{k?<div className="hint"><strong>{k.name} · v{k.version}</strong><p>{k.fingerprint}</p><code>{k.public_key.slice(0,85)}…</code></div>:<p>尚未设置</p>}{owner&&<><label>粘贴 SSH ED25519 公钥<textarea rows={5} value={keyInput[kind]} onChange={e=>setKeyInput(v=>({...v,[kind]:e.target.value}))} placeholder="ssh-ed25519 AAAAC3..."/></label><button disabled={busy||!keyInput[kind].trim()} onClick={()=>void saveKey(kind)}>保存{kind==="daily"?"日常":"救援"}公钥</button></>}</section>})}</div>}
 {owner&&page==="keys"&&<section className="card"><h3>🔐 绑定第二种登录方式</h3><p>为了防止同邮箱跨身份提供方被自动授予管理员权限，新的 GitHub / Cloudflare Access 身份必须使用已授权 Owner 生成的一次性绑定码完成绑定。</p><button disabled={busy} onClick={()=>void createLink()}>生成 5 分钟身份绑定码</button>{linkToken&&<div className="hint"><code>{linkToken}</code><p>在另一浏览器会话里使用另一身份提供方登录，再粘贴此绑定码。不要分享给其他人。</p></div>}</section>}
 {me&&page==="audit"&&owner&&<section className="card"><h3>最近 100 条审计事件</h3>{audit.map((entry,i)=><div className="audit" key={i}><b>{entry.action}</b><span>{entry.node_id||"平台"} · {entry.result}</span><small>{new Date(entry.created_at*1000).toLocaleString()}</small></div>)}{!audit.length&&<p>暂无审计记录或没有权限。</p>}</section>}
 </main></div>;
}
createRoot(document.getElementById("root")!).render(<App/>);

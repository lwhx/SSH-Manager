import React,{useEffect,useState} from "react";
import{createRoot}from"react-dom/client";
import "./style.css";
type NodeInfo={id:string;name:string;ssh_host:string;ssh_port:number;login_user:string;status:string;init_stage:string;last_seen_at?:number;config_revision:string};
type KeyInfo={id:string;purpose:string;fingerprint:string;public_key:string;version:number;name:string};
async function api<T>(path:string,method="GET",data?:unknown,headers?:Record<string,string>):Promise<T>{
 const res=await fetch("/api/v1"+path,{method,headers:{"Content-Type":"application/json",...headers},body:data?JSON.stringify(data):undefined,credentials:"same-origin"});
 const result:any=await res.json();
 if(!res.ok)throw new Error(result.error||"REQUEST_FAILED");return result;
}
function App(){
 const [me,setMe]=useState<{email:string;role:string}|null>(null);
 const [nodes,setNodes]=useState<NodeInfo[]>([]);
 const [keys,setKeys]=useState<KeyInfo[]>([]);
 const [page,setPage]=useState<"dashboard"|"nodes"|"keys"|"audit">("dashboard");
 const [selected,setSelected]=useState<NodeInfo|null>(null);
 const [message,setMessage]=useState("");
 const [draft,setDraft]=useState({name:"",ssh_host:"",login_user:"root",ssh_port:22});
 const [pair,setPair]=useState<{node_id:string;token:string}|null>(null);
 const [keyInput,setKeyInput]=useState({daily:"",rescue:""});
 const [audit,setAudit]=useState<any[]>([]);
 const [operation,setOperation]=useState<string|null>(null);
 const [linkToken,setLinkToken]=useState("");
 const [linkInput,setLinkInput]=useState("");
 const [operationState,setOperationState]=useState<{status:string;result_code?:string;detail?:string}|null>(null);
 const [busy,setBusy]=useState(false);
 const owner=me?.role==="owner";
 function alertError(e:unknown){setMessage(e instanceof Error?e.message:String(e));}
 async function refresh(){
  try{
   const u=await api<{email:string;role:string}>("/me");setMe(u);
   const n=await api<{nodes:NodeInfo[]}>("/nodes");setNodes(n.nodes);
   setSelected(previous=>previous?n.nodes.find(node=>node.id===previous.id)||null:null);
   if(u.role!=="viewer"){const k=await api<{keys:KeyInfo[]}>("/keys");setKeys(k.keys);}
  }catch(e){alertError(e);}
 }
 useEffect(()=>{void refresh();},[]);
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
 async function createNode(){await act(async()=>{const result=await api<{node_id:string;token:string}>("/nodes","POST",draft);setPair(result);setDraft({name:"",ssh_host:"",login_user:"root",ssh_port:22});setPage("nodes");});}
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
 async function installDaily(node:NodeInfo){
  if(!confirm("仅对 "+node.name+"（"+node.login_user+"）部署日常公钥？不关闭密码登录。"))return;
  await act(async()=>{const result=await api<{operation_id:string}>("/nodes/"+node.id+"/daily-key/install","POST",{},{"Idempotency-Key":crypto.randomUUID()});setOperation(result.operation_id);setOperationState(null);setMessage("已请求安装；需要等待 Agent 回报，不代表已经安装成功。");});
 }
 async function loadAudit(){await act(async()=>{setAudit((await api<{entries:any[]}>("/audit")).entries);setPage("audit");});}
 const nav=[["dashboard","仪表盘"],["nodes","VPS 管理"],["keys","双公钥管理"],["audit","操作审计"]] as const;
 return <div className="layout"><aside className="sidebar"><h2>🛡️ SSH Manager</h2><small>Cloudflare · Agent 安全管理</small><nav>{nav.map(([id,title])=><button key={id} className={page===id?"active":""} onClick={()=>{setPage(id);setSelected(null);if(id==="audit")void loadAudit();}}>{title}</button>)}</nav><div className="account">{me?me.email+" · "+me.role:"等待 Cloudflare Access 验证"}</div></aside><main className="main">
 <header><div><h1>{page==="dashboard"?"安全总览":page==="nodes"?"VPS 节点管理":page==="keys"?"SSH 公钥管理":"操作审计"}</h1><p>所有危险 SSH 修改必须人工执行；当前版本尚未启用密码认证变更与救援。</p></div><button className="secondary" onClick={()=>void refresh()}>刷新数据</button></header>
 {message&&<div className="notice" role="status">{message}<button onClick={()=>setMessage("")}>×</button></div>}
 {!me&&<section className="card"><h3>等待 SSH Manager 授权</h3><p>请先通过 Cloudflare Access 使用 GitHub 或 Cloudflare 账户认证。如果这是第二个身份提供方，需要 Owner 从已授权会话生成一次性绑定码。</p><label>5 分钟身份绑定码<input value={linkInput} onChange={e=>setLinkInput(e.target.value)} placeholder="粘贴已授权 Owner 提供的绑定码"/></label><button disabled={busy||!linkInput.trim()} onClick={()=>void claimLink()}>验证并绑定另一登录身份</button></section>}
 {me&&page==="dashboard"&&<><div className="stats"><section className="card"><small>节点总数</small><strong>{nodes.length}</strong></section><section className="card"><small>Agent 在线</small><strong>{nodes.filter(n=>n.status==="online"&&(n.last_seen_at||0)>Date.now()/1000-90).length}</strong></section><section className="card"><small>待验证节点</small><strong>{nodes.filter(n=>n.init_stage!=="COMPLETE").length}</strong></section></div><section className="card"><h3>安全边界</h3><p>日常公钥初始化与可信 SSH 验证是正式关闭密码登录的前置条件。紧急救援公钥仅可由管理员在单台 VPS 上手动启用。当前基础版本不允许任何自动回滚。</p><button onClick={()=>setPage("nodes")}>进入节点管理</button></section></>}
 {me&&page==="nodes"&&<div className="columns"><div><section className="card"><h3>VPS 列表</h3>{nodes.map(n=><button key={n.id} className="node" onClick={()=>{setSelected(n);setOperation(null);setOperationState(null);}}><b>{n.name}</b><span>{n.ssh_host}:{n.ssh_port} · {n.login_user}</span><em>{n.init_stage} · {n.status}</em></button>)}{!nodes.length&&<p>暂无 VPS。请先添加并配对 Agent。</p>}</section>{me.role!=="viewer"&&<section className="card"><h3>添加 VPS</h3><label>节点名称<input value={draft.name} onChange={e=>setDraft(v=>({...v,name:e.target.value}))}/></label><label>服务器 IP 或域名<input value={draft.ssh_host} onChange={e=>setDraft(v=>({...v,ssh_host:e.target.value}))}/></label><label>登录用户<input value={draft.login_user} onChange={e=>setDraft(v=>({...v,login_user:e.target.value}))}/></label><label>SSH 端口<input type="number" value={draft.ssh_port} onChange={e=>setDraft(v=>({...v,ssh_port:Number(e.target.value)}))}/></label><button disabled={busy} onClick={()=>void createNode()}>创建节点和配对令牌</button>{pair&&<div className="hint"><p>配对令牌（仅显示本次）：</p><code>{pair.token}</code><p>Node ID: {pair.node_id}</p><p>配对令牌有效期 10 分钟。请勿公开分享。</p></div>}</section>}</div><div>{selected?<section className="card"><h3>{selected.name}</h3><p>{selected.ssh_host}:{selected.ssh_port} · 用户 {selected.login_user}</p><p>Agent：{selected.status} · 初始化：{selected.init_stage}</p><p>当前配置版本：{selected.config_revision}</p><button disabled={busy||selected.status!=="online"} onClick={()=>void preflight(selected)}>执行 SSH 只读环境检查</button><button disabled={busy||selected.status!=="online"} onClick={()=>void inspectPolicy(selected)}>检查 SSH 实际生效配置（Helper）</button><button disabled={busy||selected.status!=="online"||selected.config_revision==="unverified"||!keys.some(k=>k.purpose==="daily")} onClick={()=>void installDaily(selected)}>部署日常公钥（不关闭密码）</button><hr/><h4>SSH 登录验证</h4><p>可信登录验证引擎尚在开发。关闭密码认证前必须完成真实 SSH 会话验证。</p><button disabled>开始真实 SSH 验证（待实现）</button><button disabled className="danger">关闭密码登录（安全锁定）</button><hr/><h4>单节点紧急救援</h4><p>仅能针对本节点手动操作。不能批量生效。</p><button disabled>临时启用救援公钥（待实现）</button><button disabled>手动恢复密码认证（待实现）</button>{operation&&<div className="hint"><p>任务 ID：{operation}</p><p>实际状态：{operationState?.status||"等待 Agent"} · {operationState?.result_code||""}</p>{operationState?.detail&&<pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{operationState.detail}</pre>}<small>配置检查不能代替可信 SSH 登录验证；安装日常公钥不会关闭密码登录。</small></div>}</section>:<section className="card"><h3>选择一台 VPS</h3><p>操作仅对当前选中的服务器生效。</p></section>}</div></div>}
 {me&&page==="keys"&&<div className="columns">{(["daily","rescue"] as const).map(kind=>{const k=keys.find(k=>k.purpose===kind);return <section className="card" key={kind}><h3>{kind==="daily"?"🔑 日常公钥":"🛟 救援公钥"}</h3><p>{kind==="daily"?"只在单节点初始化时授权安装。":"默认不对任何 VPS 生效；保存公钥不会下发救援授权。"}</p>{k?<div className="hint"><strong>{k.name} · v{k.version}</strong><p>{k.fingerprint}</p><code>{k.public_key.slice(0,85)}…</code></div>:<p>尚未设置</p>}{owner&&<><label>粘贴 SSH ED25519 公钥<textarea rows={5} value={keyInput[kind]} onChange={e=>setKeyInput(v=>({...v,[kind]:e.target.value}))} placeholder="ssh-ed25519 AAAAC3..."/></label><button disabled={busy||!keyInput[kind].trim()} onClick={()=>void saveKey(kind)}>保存{kind==="daily"?"日常":"救援"}公钥</button></>}</section>})}</div>}
 {owner&&page==="keys"&&<section className="card"><h3>🔐 绑定第二种登录方式</h3><p>为了防止同邮箱跨身份提供方被自动授予管理员权限，新的 GitHub / Cloudflare Access 身份必须使用已授权 Owner 生成的一次性绑定码完成绑定。</p><button disabled={busy} onClick={()=>void createLink()}>生成 5 分钟身份绑定码</button>{linkToken&&<div className="hint"><code>{linkToken}</code><p>在另一浏览器会话里使用另一身份提供方登录，再粘贴此绑定码。不要分享给其他人。</p></div>}</section>}
 {me&&page==="audit"&&<section className="card"><h3>最近 100 条审计事件</h3>{audit.map((entry,i)=><div className="audit" key={i}><b>{entry.action}</b><span>{entry.node_id||"平台"} · {entry.result}</span><small>{new Date(entry.created_at*1000).toLocaleString()}</small></div>)}{!audit.length&&<p>暂无审计记录或没有权限。</p>}</section>}
 </main></div>;
}
createRoot(document.getElementById("root")!).render(<App/>);

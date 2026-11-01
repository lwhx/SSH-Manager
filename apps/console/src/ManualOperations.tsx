import React,{useEffect,useState} from "react";
import {presentConsoleError} from "./errorPresentation";

type Node={id:string;name:string;status:string;init_stage:string;login_user:string};
type Snapshot={id:string;local_ref:string;revision:string;restored_at:number|null;created_at:number};
type Rescue={active:boolean;installed:{fingerprint:string;version:number}|null};
type ManualAction="ssh/password/disable"|"ssh/password/restore"|"ssh/config/rollback"|"rescue/enable"|"rescue/revoke";
type Props={node:Node;owner:boolean;enabled:boolean;rescueKeyAvailable:boolean;onOperation:(id:string)=>void};
const titles:Record<ManualAction,string>={
 "ssh/password/disable":"人工关闭 SSH 密码认证",
 "ssh/password/restore":"人工恢复原有密码认证策略",
 "ssh/config/rollback":"人工回滚 SSH Manager 配置快照",
 "rescue/enable":"仅为本 VPS 启用救援公钥",
 "rescue/revoke":"仅从本 VPS 撤销救援公钥"
};
async function request<T>(url:string,method="GET",payload?:unknown):Promise<T>{
 const res=await fetch("/api/v1"+url,{method,credentials:"same-origin",
  headers:{"Content-Type":"application/json",...(method!=="GET"?{"Idempotency-Key":crypto.randomUUID()}:{})},
  body:payload?JSON.stringify(payload):undefined});
 const data:any=await res.json();
 if(!res.ok)throw new Error(presentConsoleError(data.error));
 return data;
}

export default function ManualOperations({node,owner,enabled,rescueKeyAvailable,onOperation}:Props){
 const [nodeIdInput,setNodeIdInput]=useState("");
 const [reason,setReason]=useState("");
 const [snapshotRef,setSnapshotRef]=useState("");
 const [snapshots,setSnapshots]=useState<Snapshot[]>([]);
 const [rescue,setRescue]=useState<Rescue>({active:false,installed:null});
 const [lastOperation,setLastOperation]=useState("");
 const [lastStatus,setLastStatus]=useState("");
 const [notice,setNotice]=useState("");
 const [busy,setBusy]=useState(false);
 const ready=owner&&enabled&&node.status==="online"&&nodeIdInput===node.id&&
  reason.trim()===reason&&reason.length>=12&&reason.length<=280;
 async function refresh(){
  const [s,r]=await Promise.all([
   request<{snapshots:Snapshot[]}>("/nodes/"+node.id+"/snapshots"),
   request<Rescue>("/nodes/"+node.id+"/rescue/state")
  ]);
  setSnapshots(s.snapshots);setRescue(r);
 }
 useEffect(()=>{
  if(!owner)return;
  let active=true;
  void Promise.all([
   request<{snapshots:Snapshot[]}>("/nodes/"+node.id+"/snapshots"),
   request<Rescue>("/nodes/"+node.id+"/rescue/state")
  ]).then(([s,r])=>{if(active){setSnapshots(s.snapshots);setRescue(r);}})
    .catch(e=>{if(active)setNotice(e instanceof Error?e.message:String(e));});
  return()=>{active=false};
 },[node.id,owner]);
 useEffect(()=>{
  if(!lastOperation)return;
  let active=true;
  let lastSeen="";
  const check=async()=>{
   try{
    const value=await request<{operation:{status:string}}>("/operations/"+lastOperation);
    if(!active)return;
    setLastStatus(value.operation.status);
    if(value.operation.status==="SUCCEEDED"&&lastSeen!=="SUCCEEDED"){
     lastSeen="SUCCEEDED";
     await refresh();
    }
   }catch(e){if(active)setNotice(e instanceof Error?e.message:String(e));}
  };
  void check();
  const timer=setInterval(()=>void check(),3000);
  return()=>{active=false;clearInterval(timer)};
 },[lastOperation,node.id]);
 async function execute(action:ManualAction){
  if(!ready||busy)return;
  if((action==="ssh/password/restore"||action==="ssh/config/rollback")&&!snapshotRef){
   setNotice("必须选择当前节点的未恢复快照。");return;
  }
  if(!window.confirm(titles[action]+"\n节点："+node.name+"\nUUID："+node.id+
   "\n将只下发到这一台 VPS，绝不自动回滚。请确认服务商控制台可用。"))return;
  setBusy(true);setNotice("");
  try{
   const result=await request<{operation_id:string}>("/nodes/"+node.id+"/"+action,"POST",{
    confirm_node_id:node.id,reason,
    ...(action==="ssh/password/restore"||action==="ssh/config/rollback"?{snapshot_ref:snapshotRef}:{})
   });
   setLastOperation(result.operation_id);setLastStatus("QUEUED");
   onOperation(result.operation_id);
   setNodeIdInput("");setReason("");
   setNotice("已下发到当前 VPS；云端必须核验 Root 签名回执后才能认定成功。");
  }catch(e){setNotice(e instanceof Error?e.message:String(e));}
  finally{setBusy(false);}
 }
 return <section className="danger-panel">
  <h4>⚠️ 本 VPS 的人工 SSH 修改与救援</h4>
  <p className="warning">先确认云服务商控制台可用，保留现有 SSH 连接。所有操作需单节点确认，不自动下发到其他 VPS，不以断线或登录失败触发回滚。</p>
  {!enabled&&<p className="safety-locked">云端高危操作开关尚未开启：MANUAL_SSH_ACTIONS_ENABLED=false，当前所有危险按钮均锁定。</p>}
  <p>当前救援状态：{rescue.active?"已启用，必须人工撤销":"未启用"}{rescue.installed&&<> · <code>{rescue.installed.fingerprint}</code></>}</p>
  {owner&&<>
   <label>手工输入当前 VPS 完整 UUID
    <input value={nodeIdInput} onChange={e=>setNodeIdInput(e.target.value)} placeholder={node.id}/>
   </label>
   <label>操作原因（至少 12 字符，写入审计）
    <textarea rows={2} value={reason} onChange={e=>setReason(e.target.value)}
     placeholder="例如：已在本台 VPS 上验证新 SSH 公钥登录，并留有控制台救援入口"/>
   </label>
   <label>选择尚未恢复的 SSH Manager 配置快照（仅恢复/回滚使用）
    <select value={snapshotRef} onChange={e=>setSnapshotRef(e.target.value)}>
     <option value="">未选择</option>
     {snapshots.filter(x=>x.restored_at==null).map(x=><option key={x.id} value={x.local_ref}>{x.local_ref} · {new Date(x.created_at*1000).toLocaleString()}</option>)}
    </select>
   </label>
   <button className="danger" disabled={!ready||busy||node.init_stage!=="KEY_VERIFIED"}
    onClick={()=>void execute("ssh/password/disable")}>人工关闭密码认证（需新近 VERIFIED）</button>
   <button className="danger" disabled={!ready||busy||node.init_stage!=="PASSWORD_DISABLED"||!snapshotRef}
    onClick={()=>void execute("ssh/password/restore")}>人工恢复原密码策略</button>
   <button className="secondary" disabled={!ready||busy||node.init_stage!=="PASSWORD_DISABLED"||!snapshotRef}
    onClick={()=>void execute("ssh/config/rollback")}>手动回滚 SSH Manager 快照</button>
   <button disabled={!ready||busy||rescue.active||!rescueKeyAvailable}
    onClick={()=>void execute("rescue/enable")}>仅本 VPS 启用救援公钥</button>
   <button className="secondary" disabled={!ready||busy||!rescue.active}
    onClick={()=>void execute("rescue/revoke")}>仅本 VPS 撤销救援公钥</button>
  </>}
  <p>“恢复密码策略”只移除 SSH Manager 自身管理的配置片段，不保证账户有可用密码，也不会自动修改其他 OpenSSH 或系统配置。</p>
  {lastOperation&&<p>当前操作：<code>{lastOperation}</code> · {lastStatus}</p>}
  {notice&&<p role="status">{notice}</p>}
 </section>;
}

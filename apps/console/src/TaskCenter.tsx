import React,{useEffect,useMemo,useState} from "react";
import {operationStatusPresentation} from "./operationPresentation";
import {presentConsoleError} from "./errorPresentation";
export interface TaskItem{
 id:string;node_id:string;action:string;status:string;result_code?:string|null;detail?:string|null;
 created_at:number;expires_at:number;finished_at?:number|null;
}
export interface TaskNode{id:string;name:string;}
interface Props{nodes:TaskNode[];nodeId?:string;onOpenNode:(id:string)=>void;}
export default function TaskCenter({nodes,nodeId,onOpenNode}:Props){
 const [rows,setRows]=useState<TaskItem[]>([]);
 const [status,setStatus]=useState("all");
 const [filterNode,setFilterNode]=useState("all");
 const [loading,setLoading]=useState(true);
 const [error,setError]=useState("");
 const [version,setVersion]=useState(0);
 useEffect(()=>{
  let alive=true,loadingRequest=false;
  const controller=new AbortController();
  async function load(){
   if(loadingRequest)return;
   loadingRequest=true;
   try{
    const suffix=nodeId?"?node_id="+encodeURIComponent(nodeId):"";
    const response=await fetch("/api/v1/operations"+suffix,{credentials:"same-origin",signal:controller.signal});
    const result=await response.json() as {operations?:TaskItem[];error?:string};
    if(!response.ok)throw new Error(presentConsoleError(result.error));
    if(alive){setRows(result.operations||[]);setError("");}
   }catch(e){if(alive&&!controller.signal.aborted)setError(e instanceof Error?e.message:String(e));}
   finally{loadingRequest=false;if(alive)setLoading(false);}
  }
  setLoading(true);setRows([]);
  void load();
  const timer=window.setInterval(()=>void load(),8000);
  return()=>{alive=false;controller.abort();window.clearInterval(timer);};
 },[nodeId,version]);
 const names=useMemo(()=>new Map(nodes.map(n=>[n.id,n.name])),[nodes]);
 const visible=rows.filter(op=>{
  const presentation=operationStatusPresentation(op.status);
  if(status==="unknown"&&op.status!=="RESULT_UNKNOWN")return false;
  if(status==="failed"&&presentation.tone!=="danger")return false;
  if(status==="running"&&presentation.terminal)return false;
  if(status==="success"&&op.status!=="SUCCEEDED")return false;
  return Boolean(nodeId||filterNode==="all"||op.node_id===filterNode);
 });
 return <section className="card task-center">
  <div className="directory-header"><div><h3>{nodeId?"当前节点操作记录":"任务中心"}</h3><p>最近 100 条操作。此页面只展示状态，不会重新执行命令。</p></div>
   <button className="secondary" onClick={()=>setVersion(v=>v+1)}>刷新任务</button>
  </div>
  <p className="safety-locked">⚠ RESULT_UNKNOWN 表示回执未得到确认，不能认定成功，也不要重复提交危险操作。请先通过 VPS 服务商控制台核实。</p>
  <div className="directory-toolbar task-filters">
   {!nodeId&&<select aria-label="节点筛选" value={filterNode} onChange={e=>setFilterNode(e.target.value)}><option value="all">所有节点</option>
    {nodes.map(n=><option key={n.id} value={n.id}>{n.name}</option>)}</select>}
   <select aria-label="任务状态筛选" value={status} onChange={e=>setStatus(e.target.value)}>
    <option value="all">所有状态</option><option value="running">未完结</option><option value="success">成功</option><option value="failed">异常</option><option value="unknown">结果未知</option>
   </select>
  </div>
  {error&&<p role="alert" className="safety-locked">加载任务失败：{error}</p>}
  {loading&&<p role="status">正在读取任务记录…</p>}
  {!loading&&<div className="directory-scroll"><table className="directory-table">
   <thead><tr><th>时间</th><th>节点</th><th>操作</th><th>状态</th><th>结果</th></tr></thead>
   <tbody>{visible.map(op=>{const shown=operationStatusPresentation(op.status);return <tr key={op.id}>
    <td>{new Date(op.created_at*1000).toLocaleString()}</td>
    <td>{names.has(op.node_id)?<button className="text-button" onClick={()=>onOpenNode(op.node_id)}>{names.get(op.node_id)}</button>:<code>{op.node_id}</code>}</td>
    <td><strong>{op.action}</strong><small>{op.id}</small></td>
    <td><span className={"operation-status "+shown.tone}>{shown.label}</span></td>
    <td>{op.result_code||"—"}{op.detail&&<details><summary>查看详情</summary><pre>{op.detail}</pre></details>}</td>
   </tr>;})}</tbody></table>
   {!visible.length&&<p>{error?"暂无可显示数据":"没有符合筛选条件的操作任务。"}</p>}
  </div>}
 </section>;
}

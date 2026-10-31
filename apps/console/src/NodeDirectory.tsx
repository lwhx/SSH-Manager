import React,{useState} from "react";
import {DirectoryNode,filterNodes,isNodeOnline} from "./nodeDisplay";
export default function NodeDirectory<T extends DirectoryNode & {ssh_port:number;config_revision:string}>({
 nodes,onSelect,onCreate,canCreate
}:{nodes:T[];onSelect:(node:T)=>void;onCreate:()=>void;canCreate:boolean}){
 const [search,setSearch]=useState("");
 const [status,setStatus]=useState("all");
 const [group,setGroup]=useState("all");
 const [sort,setSort]=useState<"name"|"recent">("recent");
 const filtered=filterNodes(nodes,{search,status,group,sort});
 const groups=Array.from(new Set(nodes.map(n=>n.group_name||"").filter(Boolean)));
 return <><div className="directory-header"><div><h2>服务器列表</h2><p>查看节点、Agent 在线状态和 SSH 初始化进度</p></div>{canCreate&&<button onClick={onCreate}>＋ 添加 VPS</button>}</div>
 <section className="card"><div className="directory-toolbar">
  <input aria-label="搜索 VPS" value={search} onChange={e=>setSearch(e.target.value)} placeholder="搜索名称、IP、登录用户"/>
  <select aria-label="状态筛选" value={status} onChange={e=>setStatus(e.target.value)}><option value="all">全部状态</option><option value="online">在线</option><option value="offline">离线</option><option value="unpaired">未配对</option></select>
  <select aria-label="分组筛选" value={group} onChange={e=>setGroup(e.target.value)}><option value="all">全部分组</option>{groups.map(g=><option value={g} key={g}>{g}</option>)}</select>
  <select aria-label="排序方式" value={sort} onChange={e=>setSort(e.target.value)}><option value="recent">最新添加</option><option value="name">名称排序</option></select>
 </div><div className="directory-scroll"><table className="directory-table"><thead><tr><th>节点</th><th>连接信息</th><th>Agent</th><th>安全初始化</th><th>分组</th><th>操作</th></tr></thead><tbody>
 {filtered.map(n=><tr key={n.id}><td><strong>{n.name}</strong></td><td>{n.ssh_host}:{n.ssh_port}<small>{n.login_user}</small></td>
 <td><span className={"status-dot "+(isNodeOnline(n)?"online":"")}/>{n.status==="unpaired"?"未配对":isNodeOnline(n)?"在线":"离线"}</td><td>{n.init_stage}</td><td>{n.group_name||"未分组"}</td>
 <td><button className="secondary" onClick={()=>onSelect(n)}>查看详情 →</button></td></tr>)}
 </tbody></table></div>{!filtered.length&&<p>没有匹配的节点。</p>}</section></>;
}
import React,{useState} from "react";
import {buildStagingInstallerCommand} from "./agentInstallCommand";

interface NodeRef{ id:string;status:string;init_stage:string;name:string;last_seen_at?:number; }
interface PairRef{node_id:string;token:string;expires_at:number;}
interface Props{
 node:NodeRef;pair:PairRef|null;gateway:string;revision:string;
 busy:boolean;canPair:boolean;onNewToken:()=>void;onRefresh:()=>void;
}
export default function AgentInstallWizard({node,pair,gateway,revision,busy,canPair,onNewToken,onRefresh}:Props){
 const [feedback,setFeedback]=useState("");
 const [expanded,setExpanded]=useState(true);
 const activePair=pair?.node_id===node.id&&pair.expires_at>Date.now()?pair:null;
 let command="";
 let issue="";
 try{command=buildStagingInstallerCommand(node.id,gateway,revision);}
 catch(e){issue=e instanceof Error?e.message:String(e);}
 async function copy(v:string,what:string){
  try{await navigator.clipboard.writeText(v);setFeedback(what+"已复制到剪贴板");}
  catch{setFeedback("浏览器复制失败，请手动选择复制");}
 }
 return <div className="installer-panel">
  <div className="installer-title">
   <h4>📦 VPS Agent 安装与配对</h4>
   <button className="secondary" onClick={()=>setExpanded(v=>!v)}>{expanded?"收起":"展开"}</button>
  </div>
  {expanded&&<>
   <p>仅用于隔离的 Debian / Ubuntu 测试 VPS。Agent 主动出站连接 <code>{gateway||"等待网关配置"}</code>，无需给 VPS 开放额外入站端口。</p>
   <p>安装器只部署 Agent 与尚未启用的 Root Helper 文件，不更改 sshd、公钥或密码登录设置。需要 Linux systemd、curl、tar、Go 1.23+。</p>
   {node.status==="unpaired"?<>
    <strong>第 1 步：在测试 VPS 终端安装</strong>
    {command?<><pre className="install-code">{command}</pre>
      <button className="secondary" disabled={busy} onClick={()=>void copy(command,"安装命令")}>复制 VPS 安装命令</button>
      <p>此命令固定到管理面板同一 Git 提交版本，不包含配对令牌；下载后可以先检查脚本内容。</p></>
    :<p className="safety-locked">当前无法生成安全的安装命令：{issue}。请确认面板由完整 Git 提交构建。</p>}
    <hr/>
    <strong>第 2 步：安装程序提示输入令牌时，再生成一次性令牌</strong>
    <p>先让 VPS 完成源码下载和编译；看见 Paste the pairing token 提示后，再点击下方按钮。生成新令牌会立即使旧令牌失效，有效期 10 分钟。</p>
    {canPair&&<button disabled={busy} onClick={onNewToken}>重新生成配对令牌（10 分钟）</button>}
    {activePair?<div className="token-surface"><p>当前节点的一次性配对令牌（仅本次显示）：</p>
      <code>{activePair.token}</code><div><button className="secondary" onClick={()=>void copy(activePair.token,"配对令牌")}>复制配对令牌</button></div>
      <p>有效至：{new Date(activePair.expires_at).toLocaleTimeString()}。请粘贴到 VPS 安装器的隐藏输入提示中，不要写进 shell 命令或日志。</p>
     </div>:<p>尚未生成新令牌，或已过期。安装器请求输入时生成即可。</p>}
    <hr/>
    <strong>第 3 步：确认 Agent 已上线</strong>
    <p>安装器会注册 ssh-manager 非 root systemd 服务；完成后点击“刷新节点状态”。若仍离线，在 VPS 执行 <code>sudo journalctl -u ssh-manager-agent -n 60 --no-pager</code> 检查。</p>
   </>:<p>当前节点已建立或正在使用 Agent 身份；为防止覆盖设备密钥，安装器不支持重复安装或重新配对。如需重装，应先走单节点人工解绑与安全恢复流程。</p>}
   <button className="secondary" onClick={onRefresh} disabled={busy}>刷新节点状态</button>
   <p><a href="https://github.com/lwhx/SSH-Manager/blob/main/docs/AGENT_STAGING_INSTALL.md" target="_blank" rel="noopener noreferrer">完整安装、排错与安全说明</a></p>
   {feedback&&<p role="status">{feedback}</p>}
  </>}
 </div>;
}

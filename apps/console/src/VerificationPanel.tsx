import React from "react";

export interface ScopedVerification {
 node_id:string;
 id:string;status:string;expires_at:number;fingerprint:string;login_user:string;
 token?:string;prepared_at?:number|null;
}
export default function VerificationPanel({
 nodeId,verification,canManage,busy,onCancel
}:{nodeId:string;verification:ScopedVerification|null;canManage:boolean;busy:boolean;onCancel:()=>void}){
 if(!verification||verification.node_id!==nodeId)return null;
 return <div className="hint">
  <strong>验证任务：{verification.status}</strong>
  <p>VPS 本机挑战准备：{verification.prepared_at?"已确认准备完成":"尚未收到成功回执"}</p>
  <p>对应用户：{verification.login_user}</p>
  <p>目标公钥：{verification.fingerprint}</p>
  <p>到期：{new Date(verification.expires_at*1000).toLocaleString()}</p>
  {canManage&&verification.token&&verification.status==="PENDING"&&<><p>一次性挑战（只在首次显示）：</p><code>{verification.token}</code></>}
  <p>{verification.status==="VERIFIED"?
   "控制端已接受当前节点的可信 Root Helper 签名认证证明。仍不自动关闭密码登录。":
   "只有经本机真实公钥认证、可信证明并通过 Cloudflare 验签，才会进入 VERIFIED。不要凭手工点击认定成功。"}
  </p>
  {verification.status==="PENDING"&&canManage&&<button className="secondary" disabled={busy} onClick={onCancel}>撤销本次挑战</button>}
 </div>;
}

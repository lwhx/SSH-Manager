import React from "react";
export default function NodeSecurityActions({
 online,busy,canManage,revisionReady,hasDailyKey,onPreflight,onInspect,onInstallDaily
}:{
 online:boolean;busy:boolean;canManage:boolean;revisionReady:boolean;hasDailyKey:boolean;
 onPreflight:()=>void;onInspect:()=>void;onInstallDaily:()=>void;
}){
 const disabled=busy||!canManage||!online;
 return <div className="node-security-actions">
  <button disabled={disabled} onClick={onPreflight}>执行 SSH 只读环境检查</button>
  <button disabled={disabled} onClick={onInspect}>检查 SSH 实际生效配置（Helper）</button>
  <button disabled={disabled||!revisionReady||!hasDailyKey} onClick={onInstallDaily}>部署日常公钥（不关闭密码）</button>
 </div>;
}

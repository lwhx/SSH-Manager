import React from "react";
import {operationStatusPresentation} from "./operationPresentation";

export interface ScopedOperation {id:string;node_id:string;}
export interface ScopedOperationResult {status:string;result_code?:string;detail?:string;}
export default function NodeOperationStatus({
 nodeId,operation,result
}:{nodeId:string;operation:ScopedOperation|null;result:ScopedOperationResult|null}){
 if(!operation||operation.node_id!==nodeId)return null;
 const rendered=result?operationStatusPresentation(result.status):null;
 return <div className="hint">
  <p>任务 ID：<code>{operation.id}</code></p>
  <p>实际状态：{rendered?<strong className={"operation-status "+rendered.tone}>{rendered.label}</strong>:"等待 Agent"} · {result?.result_code||""}</p>
  {result?.detail&&<pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{result.detail}</pre>}
  <small>结果未知时请核查当前 VPS 的实际 SSH 状态；不得凭面板结果重试高危操作。安装日常公钥不会关闭密码登录。</small>
 </div>;
}

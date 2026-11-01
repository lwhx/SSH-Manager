export type OperationTone="success"|"danger"|"neutral";
export interface OperationPresentation {label:string;tone:OperationTone;terminal:boolean;}
const statuses:Record<string,OperationPresentation>={
 SUCCEEDED:{label:"已成功",tone:"success",terminal:true},
 FAILED:{label:"执行失败",tone:"danger",terminal:true},
 REJECTED:{label:"已拒绝",tone:"danger",terminal:true},
 EXPIRED:{label:"已过期",tone:"danger",terminal:true},
 CANCELLED:{label:"已取消",tone:"neutral",terminal:true},
 RESULT_UNKNOWN:{label:"结果未知 · 请核查 VPS",tone:"danger",terminal:false},
 CREATED:{label:"等待派发",tone:"neutral",terminal:false},
 QUEUED:{label:"等待执行",tone:"neutral",terminal:false},
 DISPATCHED:{label:"已派发 · 待回执",tone:"neutral",terminal:false},
 RUNNING:{label:"执行中",tone:"neutral",terminal:false}
};
export function operationStatusPresentation(status:string):OperationPresentation {
 return statuses[status]||{label:"未知状态："+status,tone:"danger",terminal:false};
}

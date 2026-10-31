export type ConsolePage="dashboard"|"nodes"|"keys"|"tasks"|"audit"|"settings";
export type ConsoleRoute={page:ConsolePage;nodeId:string|null};
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const pages=new Set<ConsolePage>(["dashboard","nodes","keys","tasks","audit","settings"]);
export function consoleRouteHref(page:ConsolePage,nodeId?:string|null):string {
 return page==="nodes"&&nodeId&&uuid.test(nodeId)?"#/nodes/"+nodeId:"#/"+page;
}
export function parseConsoleRoute(hash:string):ConsoleRoute {
 const route=hash.replace(/^#/,"").split("?")[0];
 const parts=route.split("/").filter(Boolean);
 if(parts[0]==="nodes")return {page:"nodes",nodeId:parts.length===2&&uuid.test(parts[1])?parts[1]:null};
 if(parts.length===1&&pages.has(parts[0] as ConsolePage))return {page:parts[0] as ConsolePage,nodeId:null};
 return {page:"dashboard",nodeId:null};
}

export type NodeDetailTab="overview"|"agent"|"ssh"|"history"|"settings";
const allowedNodeTabs=new Set<NodeDetailTab>(["overview","agent","ssh","history","settings"]);
export function parseNodeDetailTab(hash:string):NodeDetailTab {
 const route=parseConsoleRoute(hash);
 if(route.page!=="nodes"||!route.nodeId)return "overview";
 const query=hash.indexOf("?");
 if(query<0)return "overview";
 const tab=new URLSearchParams(hash.slice(query+1)).get("tab");
 return tab&&allowedNodeTabs.has(tab as NodeDetailTab)?tab as NodeDetailTab:"overview";
}
export function consoleNodeTabHref(nodeId:string,tab:NodeDetailTab):string {
 const base=consoleRouteHref("nodes",nodeId);
 return tab==="overview"||base==="#/nodes"?base:base+"?tab="+tab;
}

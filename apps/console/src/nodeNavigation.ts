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

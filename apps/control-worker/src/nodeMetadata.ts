import {safeHost,safeUser} from "../../../packages/protocol/src/index";
export type NodeSettingsData={
 name:string;group_name:string;notes:string;ssh_host:string;ssh_port:number;login_user:string;status:string;
};
export function parseNodeChanges(input:Record<string,unknown>,current:NodeSettingsData):Omit<NodeSettingsData,"status"> {
 const allowed=new Set(["name","group_name","notes","ssh_host","ssh_port","login_user"]);
 if(!Object.keys(input).length||Object.keys(input).some(k=>!allowed.has(k)))throw Error("INVALID_NODE_SETTINGS");
 const name=String(input.name??current.name).trim();
 const group_name=String(input.group_name??current.group_name??"").trim();
 const notes=String(input.notes??current.notes??"").trim();
 const ssh_host=String(input.ssh_host??current.ssh_host).trim();
 const ssh_port=Number(input.ssh_port??current.ssh_port);
 const login_user=String(input.login_user??current.login_user).trim();
 if(!name||name.length>80||group_name.length>80||notes.length>2000||
    [name,group_name,notes].some(x=>/[\x00-\x1f\x7f]/.test(x))||
    !safeHost(ssh_host)||!safeUser(login_user)||
    !Number.isInteger(ssh_port)||ssh_port<1||ssh_port>65535)throw Error("INVALID_NODE_SETTINGS");
 if(current.status!=="unpaired"&&
    (ssh_host!==current.ssh_host||ssh_port!==current.ssh_port||login_user!==current.login_user))
   throw Error("PAIRED_NODE_CONNECTION_LOCKED");
 return {name,group_name,notes,ssh_host,ssh_port,login_user};
}

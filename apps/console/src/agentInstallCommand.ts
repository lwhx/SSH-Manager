// Command generation never accepts a pairing token: it must be entered at the VPS TTY.
export function buildStagingInstallerCommand(nodeId:string,gateway:string,sha:string):string{
 const id=nodeId.trim(), origin=gateway.trim(),rev=sha.trim().toLowerCase();
 if(!/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id))
  throw Error("Invalid node UUID");
 if(!/^https:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(origin))
  throw Error("Invalid Agent HTTPS origin");
 if(!/^[a-f0-9]{40}$/.test(rev))
  throw Error("A pinned source Git SHA is required to install the Agent");
 const url="https://raw.githubusercontent.com/lwhx/SSH-Manager/"+rev+"/scripts/install_agent_staging.sh";
 // mktemp creates a private (0700) directory: no predictable /tmp path
 // for another local user to swap before a privileged sudo bash call.
 return [
  "SM_INSTALL_DIR=\"$(mktemp -d)\"",
  "curl -fsSL --proto '=https' --tlsv1.2 '"+url+"' -o \"$SM_INSTALL_DIR/install.sh\" &&",
  "sudo bash \"$SM_INSTALL_DIR/install.sh\" --node-id '"+id+"' --gateway '"+origin+"' --revision '"+rev+"'",
  "rm -rf -- \"$SM_INSTALL_DIR\""
 ].join("\n");
}

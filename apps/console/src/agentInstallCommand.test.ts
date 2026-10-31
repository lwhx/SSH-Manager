import {describe,it,expect} from "vitest";
import {buildStagingInstallerCommand} from "./agentInstallCommand";
describe("pinned one-node Staging installer command",()=>{
 const id="10000000-0000-4000-8000-000000000001";
 const sha="a".repeat(40);
 it("pins source revision and HTTPS gateway without revealing pairing token",()=>{
  const command=buildStagingInstallerCommand(id,"https://agent-staging.example.net",sha);
  expect(command).toContain("/"+sha+"/scripts/install_agent_staging.sh");
  expect(command).toContain("--node-id '"+id+"'");
  expect(command).toContain("--gateway 'https://agent-staging.example.net'");
  expect(command).toContain("--revision '"+sha+"'");
  expect(command).not.toContain("--token ");
  expect(command).not.toContain("curl | bash");
 });
 it("rejects unpinned, shell-injected or insecure input",()=>{
  for(const val of ["", "main", "1234", "a".repeat(39)+"x"])
   expect(()=>buildStagingInstallerCommand(id,"https://agent-staging.example.net",val)).toThrow();
  for(const gateway of ["http://agent-staging.example.net","https://x.example.net/attack","https://x.example.net;echo x","https://x.example.net:443"])
   expect(()=>buildStagingInstallerCommand(id,gateway,sha)).toThrow();
  expect(()=>buildStagingInstallerCommand(id+";id","https://agent-staging.example.net",sha)).toThrow();
 });
});

import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {execFileSync} from "node:child_process";
const path=new URL("./install_agent_staging.sh",import.meta.url);
const src=readFileSync(path,"utf8");
test("staging Agent installer syntax and safety defaults",()=>{
 execFileSync("bash",["-n",path.pathname]);
 assert.match(src,/--revision/);
 assert.match(src,/-token-stdin/);
 assert.match(src,/\/dev\/tty/);
 assert.match(src,/sudo\/root|Run with sudo/);
 assert.match(src,/systemctl enable --now ssh-manager-agent\.service/);
 assert.doesNotMatch(src,/systemctl enable --now ssh-manager-helper\.service/);
 assert.doesNotMatch(src,/ssh\.password\.disable|PasswordAuthentication\s+no|enable_password_disable.*true/);
 assert.doesNotMatch(src,/-token\s+["'$]/);
});

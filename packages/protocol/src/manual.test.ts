import {describe,it,expect} from "vitest";
import {manualResultMatches} from "./manual";
const r="a".repeat(64),next="b".repeat(64),snap="c".repeat(32);
const fp="SHA256:"+"A".repeat(43);
describe("Root manual SSH result contracts",()=>{
 it("blocks fabricated disable results",()=>{
  const good={snapshot_ref:snap,config_hash:r,before_revision:r,
    after_revision:next,passwordauthentication:false,kbdinteractiveauthentication:false};
  expect(manualResultMatches("ssh.password.disable","PASSWORD_DISABLED",good,{},r)).toBe(true);
  expect(manualResultMatches("ssh.password.disable","PASSWORD_DISABLED",
    {...good,passwordauthentication:true},{},r)).toBe(false);
  expect(manualResultMatches("ssh.password.disable","PASSWORD_DISABLED",
    {...good,after_revision:r},{},r)).toBe(false);
 });
 it("requires exact snapshot binding for restore",()=>{
  const body={snapshot_ref:snap,config_hash:r,before_revision:r,
    after_revision:next,passwordauthentication:true,kbdinteractiveauthentication:true};
  expect(manualResultMatches("ssh.password.restore","PASSWORD_POLICY_RESTORED",
    body,{snapshot_ref:snap},r)).toBe(true);
  expect(manualResultMatches("ssh.config.rollback","SSH_CONFIG_ROLLED_BACK",
    body,{snapshot_ref:"d".repeat(32)},r)).toBe(false);
 });
 it("rejects rescue report without owned snapshot or with already-present key",()=>{
  const body={key_fingerprint:fp,file_checked:true,snapshot_ref:snap,
    before_sha256:r,after_sha256:next};
  expect(manualResultMatches("ssh.rescue.enable","RESCUE_KEY_INSTALLED",
    body,{fingerprint:fp},r)).toBe(true);
  expect(manualResultMatches("ssh.rescue.enable","RESCUE_KEY_INSTALLED",
    {...body,already_present:true},{fingerprint:fp},r)).toBe(false);
  expect(manualResultMatches("ssh.rescue.revoke","RESCUE_KEY_REVOKED",
    {...body,snapshot_ref:"invalid"},{fingerprint:fp},r)).toBe(false);
 });
});

import{describe,it,expect}from"vitest";
import{VERIFICATION_TTL_SECONDS,verificationBlocker,verificationStatus,type VerificationCandidate}from"./verification";
const revision="a".repeat(64);
function ready():VerificationCandidate{
 return {nodeOnline:true,stage:"WAITING_VERIFICATION",nodeRevision:revision,targetUser:"root",
  activeKeyId:"key-1",installedKeyId:"key-1",installedKeyUser:"root",
  lastInstallRevision:revision,lastInstallKeyId:"key-1",lastInstallUser:"root"};
}
describe("SSH verification challenge is narrowly scoped",()=>{
 it("allows starting a challenge only with matching node, key, user and revision",()=>{
  expect(verificationBlocker(ready())).toBeNull();
 });
 const changes:Array<[string,Partial<VerificationCandidate>,string]>=[
  ["offline",{nodeOnline:false},"NODE_OFFLINE"],
  ["not installed",{stage:"POLICY_INSPECTED"},"DAILY_KEY_INSTALL_REQUIRED"],
  ["uninspected",{nodeRevision:"unverified"},"POLICY_INSPECTION_REQUIRED"],
  ["key rotated",{activeKeyId:"key-2"},"INSTALLED_KEY_IS_STALE"],
  ["key mismatch",{lastInstallKeyId:"key-2"},"INSTALLED_KEY_IS_STALE"],
  ["wrong Linux user",{lastInstallUser:"another"},"TARGET_USER_MISMATCH"],
  ["new sshd rules",{lastInstallRevision:"b".repeat(64)},"CONFIG_REVISION_CHANGED"],
 ];
 for(const[name,change,code]of changes){
  it("rejects "+name,()=>expect(verificationBlocker({...ready(),...change})).toBe(code));
 }
 it("expires a challenge after five minutes without upgrading it to verified",()=>{
  expect(VERIFICATION_TTL_SECONDS).toBe(300);
  expect(verificationStatus("PENDING",1300,1299)).toBe("PENDING");
  expect(verificationStatus("PENDING",1300,1300)).toBe("EXPIRED");
  expect(verificationStatus("CANCELLED",1300,1301)).toBe("CANCELLED");
  expect(verificationStatus("VERIFIED",1300,1301)).toBe("VERIFIED");
 });
});

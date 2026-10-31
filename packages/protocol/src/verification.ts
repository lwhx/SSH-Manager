/**
 * Preconditions for *starting* an SSH authentication challenge.
 * Passing these checks does NOT prove that an SSH login succeeded.
 * The verification result may only become VERIFIED after trustworthy
 * server-observed SSH authentication evidence has been implemented.
 */
export interface VerificationCandidate {
  nodeOnline: boolean;
  stage: string;
  nodeRevision: string;
  targetUser: string;
  activeKeyId: string;
  installedKeyId: string;
  installedKeyUser: string;
  lastInstallRevision: string;
  lastInstallKeyId: string;
  lastInstallUser: string;
}
export type VerificationBlocker =
  | "NODE_OFFLINE"
  | "DAILY_KEY_INSTALL_REQUIRED"
  | "POLICY_INSPECTION_REQUIRED"
  | "INSTALLED_KEY_IS_STALE"
  | "TARGET_USER_MISMATCH"
  | "CONFIG_REVISION_CHANGED";
export function verificationBlocker(c: VerificationCandidate):VerificationBlocker|null{
  if(!c.nodeOnline)return "NODE_OFFLINE";
  if(c.stage!=="WAITING_VERIFICATION")return "DAILY_KEY_INSTALL_REQUIRED";
  if(!/^[a-f0-9]{64}$/.test(c.nodeRevision))return "POLICY_INSPECTION_REQUIRED";
  if(!c.activeKeyId||c.installedKeyId!==c.activeKeyId||c.lastInstallKeyId!==c.activeKeyId)
    return "INSTALLED_KEY_IS_STALE";
  if(!c.targetUser||c.installedKeyUser!==c.targetUser||c.lastInstallUser!==c.targetUser)
    return "TARGET_USER_MISMATCH";
  if(c.lastInstallRevision!==c.nodeRevision)return "CONFIG_REVISION_CHANGED";
  return null;
}
export const VERIFICATION_TTL_SECONDS=300;
export function verificationStatus(status:string,expiresAt:number,now:number):string{
  return status==="PENDING"&&expiresAt<=now?"EXPIRED":status;
}

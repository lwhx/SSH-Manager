package sshhelper

import (
 "context"
 "encoding/json"
 "errors"
 "os/user"
 "path/filepath"
 "strconv"
 "strings"
 "unicode"

 "github.com/lwhx/SSH-Manager/agent/internal/sshkeys"
 "github.com/lwhx/SSH-Manager/agent/internal/sshmanaged"
 "github.com/lwhx/SSH-Manager/agent/internal/sshprobe"
)
// SSHPolicyEditor is fixed by the local root process, not by any remote JSON.
type SSHPolicyEditor interface {
 Disable(context.Context,string,string,sshprobe.Effective)(sshmanaged.Result,error)
 Restore(context.Context,string,string,string,sshprobe.Effective)(sshmanaged.Result,error)
}
type ManualPayload struct {
 ConfirmNodeID string `json:"confirm_node_id"`
 LoginUser string `json:"login_user"`
 Reason string `json:"reason"`
 VerificationID string `json:"verification_id"`
 ProofID string `json:"proof_id"`
 PublicKey string `json:"public_key"`
 Fingerprint string `json:"fingerprint"`
 KeyID string `json:"key_id"`
 SnapshotRef string `json:"snapshot_ref"`
}
func isManualSSHAction(action string)bool{
 switch action{
 case "ssh.password.disable","ssh.password.restore","ssh.config.rollback","ssh.rescue.enable","ssh.rescue.revoke":
  return true
 default:return false
 }
}
func validReason(text string)bool{
 if len(text)<12||len(text)>280||strings.TrimSpace(text)!=text{return false}
 for _,r:=range text{if unicode.IsControl(r){return false}}
 return true
}
func (h *Handler) targetAccount(login string)(*user.User,int,int,error){
 a,err:=h.Lookup(login)
 if err!=nil{return nil,0,0,err}
 uid,e:=strconv.Atoi(a.Uid);if e!=nil||uid<0{return nil,0,0,errors.New("invalid uid")}
 gid,e:=strconv.Atoi(a.Gid);if e!=nil||gid<0{return nil,0,0,errors.New("invalid gid")}
 if a.Username!=login||!filepath.IsAbs(a.HomeDir){return nil,0,0,errors.New("untrusted Linux account")}
 return a,uid,gid,nil
}
func (h *Handler) executeManualSSH(ctx context.Context,cmd Command,effective sshprobe.Effective)Result{
 if !uuidRE.MatchString(cmd.Actor){return fail("MANUAL_ACTOR_REQUIRED",nil)}
 var payload ManualPayload
 if err:=json.Unmarshal(cmd.Payload,&payload);err!=nil{return fail("MANUAL_PAYLOAD_INVALID",nil)}
 if payload.ConfirmNodeID!=h.Config.NodeID||
  payload.LoginUser!=h.Config.AllowedUser||!validReason(payload.Reason){
  return fail("MANUAL_NODE_CONFIRMATION_REQUIRED",nil)
 }
 if err:=effective.DailyKeyEligibility(h.Config.AllowedUser);err!=nil{
  return fail("UNSUPPORTED_SSH_POLICY",nil)
 }
 if cmd.Action=="ssh.password.disable"{
  if !h.Config.EnablePasswordDisable||h.Managed==nil{return fail("PASSWORD_DISABLE_LOCAL_LOCKED",nil)}
  if !uuidRE.MatchString(payload.VerificationID)||!uuidRE.MatchString(payload.ProofID){
   return fail("FRESH_VERIFIED_LOGIN_REQUIRED",nil)
  }
  value,err:=h.Managed.Disable(ctx,h.Config.NodeID,h.Config.AllowedUser,effective)
  if err!=nil{return fail("PASSWORD_DISABLE_MANUAL_REVIEW",nil)}
  return Result{OK:true,Code:"PASSWORD_DISABLED",Detail:value}
 }
 if cmd.Action=="ssh.password.restore"||cmd.Action=="ssh.config.rollback"{
  if cmd.Action=="ssh.password.restore"&&!h.Config.EnablePasswordRestore||
   cmd.Action=="ssh.config.rollback"&&!h.Config.EnableConfigRollback||h.Managed==nil{
   return fail("MANUAL_RESTORE_LOCAL_LOCKED",nil)
  }
  value,err:=h.Managed.Restore(ctx,h.Config.NodeID,h.Config.AllowedUser,payload.SnapshotRef,effective)
  if err!=nil{return fail("SSH_CONFIG_RESTORE_MANUAL_REVIEW",nil)}
  code:="PASSWORD_POLICY_RESTORED"
  if cmd.Action=="ssh.config.rollback"{code="SSH_CONFIG_ROLLED_BACK"}
  return Result{OK:true,Code:code,Detail:value}
 }
 if !h.Config.EnableRescue{return fail("RESCUE_LOCAL_LOCKED",nil)}
 if !uuidRE.MatchString(payload.KeyID){return fail("RESCUE_KEY_SCOPE_MISMATCH",nil)}
 normalized,fp,err:=sshkeys.NormalizeED25519(payload.PublicKey)
 if err!=nil||normalized==""||fp!=payload.Fingerprint{return fail("RESCUE_KEY_INVALID",nil)}
 a,uid,gid,err:=h.targetAccount(payload.LoginUser)
 if err!=nil{return fail("RESCUE_LOGIN_USER_INVALID",nil)}
 var value sshkeys.Result
 if cmd.Action=="ssh.rescue.enable"{
  value,err=h.RescueInstall(a.HomeDir,uid,gid,normalized,h.Config.SnapshotRoot)
 }else{
  value,err=h.RescueRevoke(a.HomeDir,uid,gid,normalized,h.Config.SnapshotRoot)
 }
 if err!=nil{return fail("RESCUE_KEY_MANUAL_REVIEW",nil)}
 // A key already in authorized_keys without the exact manager-owned marker
 // is not safe to revoke later; never assert that we installed it.
 if cmd.Action=="ssh.rescue.enable"&&value.AlreadyPresent{
  return fail("RESCUE_ALREADY_PRESENT_UNMANAGED",nil)
 }
 if !value.FileChecked||value.Fingerprint!=fp{return fail("RESCUE_KEY_OUTCOME_INVALID",nil)}
 if cmd.Action=="ssh.rescue.enable"{
  return Result{OK:true,Code:"RESCUE_KEY_INSTALLED",Detail:value}
 }
 return Result{OK:true,Code:"RESCUE_KEY_REVOKED",Detail:value}
}

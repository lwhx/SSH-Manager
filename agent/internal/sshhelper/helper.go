// Package sshhelper implements the root-only side of SSH Manager.
// A network Agent never gains generic root execution. The helper accepts only
// explicitly signed, node-bound, short-lived, fixed-format operations.
package sshhelper

import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "os/user"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
 "time"

 "github.com/lwhx/SSH-Manager/agent/internal/sshkeys"
 "github.com/lwhx/SSH-Manager/agent/internal/sshprobe"
)

var uuidRE=regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
var accountRE=regexp.MustCompile("^[a-z_][a-z0-9_-]{0,31}[$]?$")

type Config struct{
 NodeID string `json:"node_id"`
 CommandPublicKey string `json:"command_public_key"`
 AllowedUser string `json:"allowed_user"`
 ClientAddress string `json:"client_address"`
 LocalAddress string `json:"local_address"`
 SSHPort int `json:"ssh_port"`
 SnapshotRoot string `json:"snapshot_root"`
 EnableDailyInstall bool `json:"enable_daily_install"`
}

type SignedCommand struct{
 Command string `json:"command"`
 Signature string `json:"signature"`
}
type Command struct{
 V int `json:"v"`
 ID string `json:"id"`
 NodeID string `json:"node_id"`
 Action string `json:"action"`
 Actor string `json:"actor"`
 IssuedAt int64 `json:"issued_at"`
 ExpiresAt int64 `json:"expires_at"`
 ExpectedRevision string `json:"expected_revision"`
 Payload json.RawMessage `json:"payload"`
}
type KeyPayload struct{
 LoginUser string `json:"login_user"`
 PublicKey string `json:"public_key"`
 Fingerprint string `json:"fingerprint"`
 KeyID string `json:"key_id"`
}
type Result struct{
 OK bool `json:"ok"`
 Code string `json:"code"`
 Detail any `json:"detail,omitempty"`
}

type PolicyReader func(context.Context,Config)(sshprobe.Effective,error)
type AccountLookup func(string)(*user.User,error)
type KeyInstaller func(string,int,int,string,string)(sshkeys.Result,error)

type Handler struct{
 Config Config
 Inspect PolicyReader
 Lookup AccountLookup
 Install KeyInstaller
 Journal *Journal
 Clock func()time.Time
 EUID func()int
}
func (h *Handler) defaults(){
 if h.Inspect==nil{h.Inspect=InspectEffective}
 if h.Lookup==nil{h.Lookup=user.Lookup}
 if h.Install==nil{h.Install=sshkeys.InstallDaily}
 if h.Clock==nil{h.Clock=time.Now}
 if h.EUID==nil{h.EUID=os.Geteuid}
}
func (c Config) Validate()error{
 if !uuidRE.MatchString(c.NodeID){return errors.New("invalid configured node ID")}
 if !accountRE.MatchString(c.AllowedUser){return errors.New("invalid allowed Linux user")}
 key,err:=base64.RawURLEncoding.DecodeString(c.CommandPublicKey)
 if err!=nil||len(key)!=ed25519.PublicKeySize{return errors.New("invalid command signing key")}
 if c.SSHPort<1||c.SSHPort>65535{return errors.New("invalid SSH port")}
 if c.ClientAddress==""||c.LocalAddress==""{return errors.New("explicit SSH connection address context required")}
 if !safeIP(c.ClientAddress)||!safeIP(c.LocalAddress){return errors.New("invalid SSH context IP")}
 if !filepath.IsAbs(c.SnapshotRoot)||filepath.Clean(c.SnapshotRoot)!=c.SnapshotRoot||c.SnapshotRoot=="/"{
  return errors.New("invalid snapshot root")
 }
 return nil
}
func (h *Handler) Verify(s SignedCommand)(Command,error){
 var cmd Command
 if err:=h.Config.Validate();err!=nil{return cmd,err}
 key,_:=base64.RawURLEncoding.DecodeString(h.Config.CommandPublicKey)
 signature,err:=base64.RawURLEncoding.DecodeString(s.Signature)
 if err!=nil||!ed25519.Verify(ed25519.PublicKey(key),[]byte(s.Command),signature){
  return cmd,errors.New("invalid command signature")
 }
 if len(s.Command)>8192{return cmd,errors.New("command too large")}
 if err:=json.Unmarshal([]byte(s.Command),&cmd);err!=nil{return cmd,errors.New("invalid signed command")}
 now:=time.Now()
 if h.Clock!=nil{now=h.Clock()}
 epoch:=now.Unix()
 if cmd.V!=1||!uuidRE.MatchString(cmd.ID)||cmd.NodeID!=h.Config.NodeID{
  return cmd,errors.New("wrong protocol or target node")
 }
 if cmd.IssuedAt>epoch+10||cmd.ExpiresAt<=epoch||cmd.ExpiresAt<=cmd.IssuedAt||cmd.ExpiresAt>cmd.IssuedAt+60{
  return cmd,errors.New("stale or excessive TTL")
 }
 if cmd.Action!="ssh.policy.inspect"&&cmd.Action!="ssh.daily.install"{
  return cmd,errors.New("action denied")
 }
 if cmd.ExpectedRevision==""{return cmd,errors.New("missing expected config revision")}
 return cmd,nil
}
func fail(code string,err error)Result{
 // Never return command bytes, private material, paths or arbitrary stderr.
 if err==nil{return Result{Code:code}}
 return Result{Code:code,Detail:map[string]string{"reason":err.Error()}}
}
func (h *Handler) Execute(ctx context.Context,s SignedCommand)Result{
 h.defaults()
 cmd,err:=h.Verify(s)
 if err!=nil{return fail("COMMAND_REJECTED",err)}
 if h.Journal==nil{return fail("JOURNAL_UNAVAILABLE",nil)}
 // Only one root helper instance should own the journal and listener.
 // Reserve before any action, including read-only inspection.
 if err=h.Journal.Claim(cmd.ID);err!=nil{return fail("DUPLICATE_OR_UNSAFE_OPERATION",err)}
 if h.EUID()!=0{return fail("ROOT_REQUIRED",nil)}
 p,err:=h.Inspect(ctx,h.Config)
 if err!=nil{return fail("SSHD_INSPECTION_FAILED",err)}
 if err=p.DailyKeyEligibility(h.Config.AllowedUser);err!=nil{return fail("UNSUPPORTED_SSH_POLICY",err)}
 if cmd.Action=="ssh.policy.inspect"{
  return Result{OK:true,Code:"POLICY_INSPECTED",Detail:map[string]any{
   "revision":p.Revision,"login_user":h.Config.AllowedUser,
   "publickeyauthentication":p.PublicKeyAuthentication,
   "passwordauthentication":p.PasswordAuthentication,
   "kbdinteractiveauthentication":p.KeyboardInteractive,
   "authorizedkeysfile":p.AuthorizedKeysFile,
   "verified_login":false,
  }}
 }
 if !h.Config.EnableDailyInstall{return fail("DAILY_INSTALL_DISABLED",nil)}
 if cmd.ExpectedRevision=="unverified"||cmd.ExpectedRevision!=p.Revision{
  return fail("POLICY_REVISION_MISMATCH",nil)
 }
 var payload KeyPayload
 if err=json.Unmarshal(cmd.Payload,&payload);err!=nil{return fail("INVALID_KEY_PAYLOAD",err)}
 if payload.LoginUser!=h.Config.AllowedUser||!uuidRE.MatchString(payload.KeyID){
  return fail("USER_OR_KEY_SCOPE_MISMATCH",nil)
 }
 normalized,fingerprint,err:=sshkeys.NormalizeED25519(payload.PublicKey)
 if err!=nil{return fail("INVALID_DAILY_KEY",err)}
 if fingerprint!=payload.Fingerprint||normalized==""{
  return fail("KEY_FINGERPRINT_MISMATCH",nil)
 }
 account,err:=h.Lookup(h.Config.AllowedUser)
 if err!=nil{return fail("TARGET_USER_MISSING",err)}
 uid,err:=strconv.Atoi(account.Uid)
 if err!=nil||uid<0{return fail("INVALID_USER_ID",nil)}
 gid,err:=strconv.Atoi(account.Gid)
 if err!=nil||gid<0{return fail("INVALID_GROUP_ID",nil)}
 if account.Username!=payload.LoginUser||!filepath.IsAbs(account.HomeDir){
  return fail("TARGET_USER_MISMATCH",nil)
 }
 result,err:=h.Install(account.HomeDir,uid,gid,payload.PublicKey,h.Config.SnapshotRoot)
 if err!=nil{return fail("KEY_INSTALL_FAILED",err)}
 if !result.FileChecked||result.Fingerprint!=fingerprint{return fail("KEY_INSTALL_NOT_VERIFIED",nil)}
 return Result{OK:true,Code:"DAILY_KEY_WRITTEN_AWAITING_LOGIN_PROOF",Detail:result}
}
func SafeUser(name string)bool{return accountRE.MatchString(name)}
func ValidateSnapshotRoot(root string)error{
 if !strings.HasPrefix(root,"/var/lib/ssh-manager-root/snapshots/")||filepath.Clean(root)!=root{
  return fmt.Errorf("snapshots must remain under /var/lib/ssh-manager/snapshots")
 }
 return nil
}

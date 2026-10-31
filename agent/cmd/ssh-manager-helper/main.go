// ssh-manager-helper is a Linux-only, root-runner for narrowly scoped SSH
// maintenance. It NEVER exposes generic shell execution or password changes.
package main

import (
 "context"
 "encoding/base64"
 "crypto/ed25519"
 "flag"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "log"
 "net"
 "os"
 "os/user"
 "path/filepath"
 "strconv"
 "syscall"
 "time"

 "github.com/lwhx/SSH-Manager/agent/internal/sshhelper"
 "github.com/lwhx/SSH-Manager/agent/internal/sshproof"
)

const configPath="/etc/ssh-manager/helper.json"
const socketPath="/run/ssh-manager/helper.sock"
const journalPath="/var/lib/ssh-manager-root/operations"
const challengePath="/var/lib/ssh-manager-root/challenges"
const rootProofKeyPath="/var/lib/ssh-manager-root/proof_ed25519"
const rootOutboxPath="/var/lib/ssh-manager-root/proof-outbox"
const proofSocketPath="/run/ssh-manager-proof/proof.sock"

func loadConfig()(sshhelper.Config,error){
 var c sshhelper.Config
 fd,err:=syscall.Open(configPath,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return c,err}
 f:=os.NewFile(uintptr(fd),configPath)
 defer f.Close()
 st,err:=f.Stat()
 if err!=nil{return c,err}
 stat,ok:=st.Sys().(*syscall.Stat_t)
 if !ok||stat.Uid!=0||!st.Mode().IsRegular()||st.Mode().Perm()&0077!=0{
  return c,errors.New("helper config must be root-owned regular file mode 0600")
 }
 contents,err:=io.ReadAll(io.LimitReader(f,8193))
 if err!=nil||len(contents)>8192{return c,errors.New("helper config too large")}
 if err:=json.Unmarshal(contents,&c);err!=nil{return c,err}
 if err:=c.Validate();err!=nil{return c,err}
 if err:=sshhelper.ValidateSnapshotRoot(c.SnapshotRoot);err!=nil{return c,err}
 return c,nil
}
func peerUID(conn *net.UnixConn)(uint32,error){
 raw,err:=conn.SyscallConn()
 if err!=nil{return 0,err}
 var cred *syscall.Ucred
 var sockErr error
 if err=raw.Control(func(fd uintptr){
  cred,sockErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)
 });err!=nil{return 0,err}
 if sockErr!=nil||cred==nil{return 0,errors.New("SO_PEERCRED failed")}
 return cred.Uid,nil
}
func handle(conn *net.UnixConn,uid uint32,helper *sshhelper.Handler){
 defer conn.Close()
 _ = conn.SetDeadline(time.Now().Add(15*time.Second))
 got,err:=peerUID(conn)
 if err!=nil||got!=uid{
  log.Print("refusing unauthorised local socket peer")
  return
 }
 var result sshhelper.Result
 request,err:=io.ReadAll(io.LimitReader(conn,16385))
 if err!=nil||len(request)>16384{
  result=sshhelper.Result{Code:"REQUEST_TOO_LARGE"}
 }else{
  // Local helper outbox is reachable only by the dedicated Agent UID
  // (already verified with SO_PEERCRED), not through the public WSS API.
  var local struct{
   LocalAction string `json:"local_action"`
   ProofID string `json:"proof_id"`
   Reason string `json:"reason"`
   OperationID string `json:"operation_id"`
   Action string `json:"action"`
  }
  if json.Unmarshal(request,&local)==nil&&local.LocalAction!=""{
   if local.LocalAction=="operation.recover"{
    // Agent UID came from SO_PEERCRED. Recovery is read-only: only the
    // root-owned journal and its exact node/action scope may provide a result.
    if helper.Journal==nil{
     _=json.NewEncoder(conn).Encode(map[string]any{"state":"ERROR"})
     return
    }
    recovered,e:=helper.Journal.Recover(local.OperationID,helper.Config.NodeID,local.Action)
    if e!=nil{
     _=json.NewEncoder(conn).Encode(map[string]any{"state":"ERROR"})
     return
    }
    _=json.NewEncoder(conn).Encode(recovered)
    return
   }
   if !helper.Config.EnableSSHProof||helper.Outbox==nil{
    _=json.NewEncoder(conn).Encode(map[string]any{"ok":false,"code":"PROOF_DISABLED"})
    return
   }
   switch local.LocalAction{
   case "proof.peek":
    proof,e:=helper.Outbox.Peek()
    if errors.Is(e,os.ErrNotExist){
     _=json.NewEncoder(conn).Encode(map[string]any{"ok":false,"code":"EMPTY"});return
    }
    if e!=nil{
     _=json.NewEncoder(conn).Encode(map[string]any{"ok":false,"code":"OUTBOX_UNAVAILABLE"});return
    }
    _=json.NewEncoder(conn).Encode(map[string]any{"ok":true,"proof":proof})
   case "proof.ack":
    e:=helper.Outbox.Ack(local.ProofID)
    _=json.NewEncoder(conn).Encode(map[string]any{"ok":e==nil,"code":"ACK_RECORDED"})
   case "proof.quarantine":
    e:=helper.Outbox.Quarantine(local.ProofID,local.Reason)
    if e!=nil{
     _=json.NewEncoder(conn).Encode(map[string]any{"ok":false,"code":"QUARANTINE_FAILED"})
     return
    }
    _=json.NewEncoder(conn).Encode(map[string]any{"ok":true,"code":"PROOF_QUARANTINED"})
   default:
    _=json.NewEncoder(conn).Encode(map[string]any{"ok":false,"code":"ACTION_DENIED"})
   }
   return
  }
  var cmd sshhelper.SignedCommand
  if json.Unmarshal(request,&cmd)!=nil||cmd.Command==""||cmd.Signature==""{
   result=sshhelper.Result{Code:"MALFORMED_SIGNED_COMMAND"}
  }else{
   ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
   result=helper.Execute(ctx,cmd)
   cancel()
  }
 }
 _=json.NewEncoder(conn).Encode(result)
}
func peerCredentials(conn *net.UnixConn)(*syscall.Ucred,error){
 raw,err:=conn.SyscallConn();if err!=nil{return nil,err}
 var cred *syscall.Ucred
 var callErr error
 if err=raw.Control(func(fd uintptr){
  cred,callErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)
 });err!=nil{return nil,err}
 if callErr!=nil||cred==nil{return nil,errors.New("SO_PEERCRED unavailable")}
 return cred,nil
}
func handleProof(conn *net.UnixConn,h *sshhelper.Handler){
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(12*time.Second))
 creds,err:=peerCredentials(conn)
 if err!=nil{return}
 raw,err:=io.ReadAll(io.LimitReader(conn,512))
 if err!=nil||len(raw)>511{
  _=json.NewEncoder(conn).Encode(sshhelper.ProofResult{Code:"INVALID_PROOF_REQUEST"})
  return
 }
 var request sshhelper.ProofRequest
 if json.Unmarshal(raw,&request)!=nil||request.VerificationID==""{
  _=json.NewEncoder(conn).Encode(sshhelper.ProofResult{Code:"INVALID_PROOF_REQUEST"})
  return
 }
 ctx,cancel:=context.WithTimeout(context.Background(),9*time.Second)
 defer cancel()
 // The only untrusted input here is challenge ID + nonce. The UID/PID comes
 // from kernel SO_PEERCRED. No shell commands or sudo are used by the caller.
 result:=h.ProveSession(ctx,int(creds.Pid),int(creds.Uid),request)
 _=json.NewEncoder(conn).Encode(result)
}
func serveProofSocket(h *sshhelper.Handler,groupID int)error{
 dir:=filepath.Dir(proofSocketPath)
 info,err:=os.Lstat(dir)
 if err!=nil||!info.IsDir(){return errors.New("proof runtime directory missing")}
 owner,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=0||info.Mode().Perm()&0022!=0{
  return errors.New("proof runtime directory must be root-owned and nonwritable")
 }
 if _,err=os.Lstat(proofSocketPath);err==nil{
  return errors.New("refusing to overwrite existing proof socket")
 }else if !errors.Is(err,os.ErrNotExist){return err}
 listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:proofSocketPath,Net:"unix"})
 if err!=nil{return err}
 defer listener.Close()
 if err=os.Chown(proofSocketPath,0,groupID);err!=nil{return err}
 if err=os.Chmod(proofSocketPath,0660);err!=nil{return err}
 for{
  conn,err:=listener.AcceptUnix()
  if err!=nil{return err}
  // Bounded concurrent proof sessions are required on a real VPS.
  // The semaphore prevents a local user from exhausting root helper memory.
  proofSemaphore<-struct{}{}
  go func(){defer func(){<-proofSemaphore}();handleProof(conn,h)}()
 }
}
var proofSemaphore=make(chan struct{},4)

func main(){
 if os.Geteuid()!=0{log.Fatal("ssh-manager-helper must run as root")}
 initKey:=flag.Bool("init-proof-key",false,"explicitly create a root-only per-node proof identity")
 flag.Parse()
 if *initKey{
  if flag.NArg()!=0{log.Fatal("unexpected positional arguments")}
  if err:=os.MkdirAll(filepath.Dir(rootProofKeyPath),0700);err!=nil{log.Fatal(err)}
  public,err:=sshproof.GenerateRootProofKey(rootProofKeyPath)
  if err!=nil{log.Fatal(err)}
  raw,err:=base64.RawURLEncoding.DecodeString(public)
  if err!=nil{log.Fatal(err)}
  fmt.Println("Root proof key (base64url):",public)
  fmt.Println("Root proof fingerprint:",sshproof.ProofPublicFingerprint(ed25519.PublicKey(raw)))
  return
 }
 conf,err:=loadConfig()
 if err!=nil{log.Fatal(err)}
 agentAccount,err:=user.Lookup("ssh-manager")
 if err!=nil{log.Fatal("missing dedicated ssh-manager service account: ",err)}
 uid,err:=strconv.Atoi(agentAccount.Uid)
 if err!=nil{log.Fatal(err)}
 gid,err:=strconv.Atoi(agentAccount.Gid)
 if err!=nil{log.Fatal(err)}
 dir:=filepath.Dir(socketPath)
 st,err:=os.Lstat(dir)
 if err!=nil{log.Fatal("runtime dir missing: ",err)}
 owner,ok:=st.Sys().(*syscall.Stat_t)
 if !st.IsDir()||!ok||owner.Uid!=0||st.Mode().Perm()&0027!=0{
  log.Fatal("unsafe helper runtime directory")
 }
 if _,err=os.Lstat(socketPath);err==nil{log.Fatal("helper socket already exists")}
 if !errors.Is(err,os.ErrNotExist){log.Fatal(err)}
 listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:socketPath,Net:"unix"})
 if err!=nil{log.Fatal(err)}
 defer listener.Close()
 if err=os.Chown(socketPath,0,gid);err!=nil{log.Fatal(err)}
 if err=os.Chmod(socketPath,0660);err!=nil{log.Fatal(err)}
 if err=os.MkdirAll(journalPath,0700);err!=nil{log.Fatal(err)}
 var proofSigningKey ed25519.PrivateKey
 if conf.EnableSSHProof{
  proofSigningKey,err=sshproof.LoadRootProofKey(rootProofKeyPath)
  if err!=nil{log.Fatal("proof key not provisioned: ",err)}
  if err=os.MkdirAll(rootOutboxPath,0700);err!=nil{log.Fatal(err)}
 }
 helper:=&sshhelper.Handler{
  Config:conf,Journal:&sshhelper.Journal{Directory:journalPath},
  Challenges:&sshhelper.ChallengeStore{Directory:challengePath},
  Outbox:&sshhelper.Outbox{Directory:rootOutboxPath},
  ProofSigningKey:proofSigningKey,
 }
 if conf.EnableSSHProof{
  loginUser,err:=user.Lookup(conf.AllowedUser)
  if err!=nil{log.Fatal(err)}
  loginGID,err:=strconv.Atoi(loginUser.Gid)
  if err!=nil{log.Fatal(err)}
  go func(){log.Fatal("proof socket stopped: ",serveProofSocket(helper,loginGID))}()
 }
 log.Printf("SSH Manager helper listening (node=%s, daily_install=%t)",conf.NodeID,conf.EnableDailyInstall)
 for{
  conn,err:=listener.AcceptUnix()
  if err!=nil{log.Fatal(fmt.Errorf("helper accept: %w",err))}
  // Serialize SSH modifications. Multiple signed requests cannot race on the
  // same target authorized_keys or operation journal.
  handle(conn,uint32(uid),helper)
 }
}

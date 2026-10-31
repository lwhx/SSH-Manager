// ssh-manager-helper is a Linux-only, root-runner for narrowly scoped SSH
// maintenance. It NEVER exposes generic shell execution or password changes.
package main

import (
 "context"
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
)

const configPath="/etc/ssh-manager/helper.json"
const socketPath="/run/ssh-manager/helper.sock"
const journalPath="/var/lib/ssh-manager/helper-operations"

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
func main(){
 if os.Geteuid()!=0{log.Fatal("ssh-manager-helper must run as root")}
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
 helper:=&sshhelper.Handler{Config:conf,Journal:&sshhelper.Journal{Directory:journalPath}}
 log.Printf("SSH Manager helper listening (node=%s, daily_install=%t)",conf.NodeID,conf.EnableDailyInstall)
 for{
  conn,err:=listener.AcceptUnix()
  if err!=nil{log.Fatal(fmt.Errorf("helper accept: %w",err))}
  // Serialize SSH modifications. Multiple signed requests cannot race on the
  // same target authorized_keys or operation journal.
  handle(conn,uint32(uid),helper)
 }
}

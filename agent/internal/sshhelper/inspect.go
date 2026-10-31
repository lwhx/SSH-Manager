package sshhelper

import (
 "context"
 "errors"
 "fmt"
 "net"
 "os"
 "os/exec"
 "strings"
 "time"

 "github.com/lwhx/SSH-Manager/agent/internal/sshprobe"
)
func safeIP(value string)bool{return net.ParseIP(value)!=nil}

// InspectEffective uses fixed absolute paths. Network-controlled payloads
// NEVER become arguments, executable paths or shell fragments.
func InspectEffective(parent context.Context,c Config)(sshprobe.Effective,error){
 var zero sshprobe.Effective
 if !safeIP(c.ClientAddress)||!safeIP(c.LocalAddress)||!SafeUser(c.AllowedUser)||
  c.SSHPort<1||c.SSHPort>65535{return zero,errors.New("invalid SSH connection context")}
 const binary="/usr/sbin/sshd"
 const config="/etc/ssh/sshd_config"
 info,err:=os.Lstat(binary)
 if err!=nil||!info.Mode().IsRegular()||info.Mode()&0111==0{
  return zero,errors.New("expected absolute sshd executable not found")
 }
 ctx,cancel:=context.WithTimeout(parent,8*time.Second)
 defer cancel()
 verify:=exec.CommandContext(ctx,binary,"-t","-f",config)
 if out,err:=verify.CombinedOutput();err!=nil{
  _=out
  return zero,fmt.Errorf("sshd syntax check failed: %w",err)
 }
 // host is deliberately the exact client IP; hostname-sensitive Match rules
 // are NOT considered verified by this inspection. True login proof is separate.
 contextValue:=fmt.Sprintf("user=%s,host=%s,addr=%s,laddr=%s,lport=%d",
  c.AllowedUser,c.ClientAddress,c.ClientAddress,c.LocalAddress,c.SSHPort)
 command:=exec.CommandContext(ctx,binary,"-T","-f",config,"-C",contextValue)
 stdout,err:=command.Output()
 if err!=nil{return zero,fmt.Errorf("sshd effective config check failed: %w",err)}
 policy,err:=sshprobe.ParseEffective(string(stdout))
 if err!=nil{return zero,err}
 if len(policy.AuthorizedKeysFile)!=1||strings.TrimSpace(policy.AuthorizedKeysFile[0])!=".ssh/authorized_keys"{
  return zero,errors.New("unsupported effective AuthorizedKeysFile")
 }
 return policy,nil
}

package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/url"
 "os"
 "os/user"
 "path/filepath"
 "strconv"
 "strings"
 "syscall"
)

const defaultAgentStateDir="/var/lib/ssh-manager-agent"
const defaultAgentHelperSocket="/run/ssh-manager/helper.sock"
const standardAgentConfig="/etc/ssh-manager/agent.json"

// Pairing must write both locations used at runtime. Empty fields in a
// legacy pairing file are upgraded in-memory to the SAME safe defaults.
func normalizeAgentConfig(c *Config)error{
 if c.HelperSocket==""{c.HelperSocket=defaultAgentHelperSocket}
 if c.HelperSocket!=defaultAgentHelperSocket{
  return errors.New("agent helper socket must be the fixed local root-helper endpoint")
 }
 if c.StateDir==""{c.StateDir=defaultAgentStateDir}
 if !filepath.IsAbs(c.StateDir)||filepath.Clean(c.StateDir)!=c.StateDir||
  c.StateDir=="/"{
  return errors.New("unsafe agent persistent state directory")
 }
 u,err:=url.Parse(c.Gateway)
 if err!=nil||u.Scheme!="https"||u.Host==""||u.User!=nil||
  (u.Path!=""&&u.Path!="/")||u.RawQuery!=""||u.Fragment!=""{
  return errors.New("agent gateway must be an HTTPS origin without credentials or path")
 }
 if !operationID.MatchString(c.NodeID){return errors.New("invalid paired node ID")}
 return nil
}

// Check the destination BEFORE consuming the one-time Cloudflare pairing
// token. An unwritable or existing Agent config should not strand a device
// pairing that can no longer be retried.
func validatePairingDestination(path string)error{
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path||path=="/"{
  return errors.New("paired Agent config needs a safe absolute filename")
 }
 if _,err:=os.Lstat(path);err==nil{
  return errors.New("refusing to overwrite existing Agent device credentials")
 }else if !os.IsNotExist(err){return err}
 if path==standardAgentConfig{
  if os.Geteuid()!=0{return errors.New("pair as root after provisioning ssh-manager service account")}
  if _,err:=user.Lookup("ssh-manager");err!=nil{return fmt.Errorf("ssh-manager service account missing: %w",err)}
 }
 if stat,err:=os.Lstat(filepath.Dir(path));err==nil{
  if !stat.IsDir()||stat.Mode().Perm()&0022!=0{
   return errors.New("untrusted Agent config directory")
  }
  if path==standardAgentConfig{
   owner,ok:=stat.Sys().(*syscall.Stat_t)
   if !ok||owner.Uid!=0{return errors.New("standard Agent config directory must be root-owned")}
  }
 }else if !os.IsNotExist(err){return err}
 return nil
}

// Only the standard systemd config path is group-traversable. The Agent UID
// owns the 0600 device config; the root Helper config stays root-only 0600.
// This is a FILE permission change during an explicit pairing operation,
// never an SSH change or privileged management action.
func savePairingConfig(path string,c Config)error{
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path||path=="/"{
  return errors.New("paired Agent config needs a safe absolute filename")
 }
 if err:=normalizeAgentConfig(&c);err!=nil{return err}
 dir:=filepath.Dir(path)
 uid,gid:=-1,-1
 if path==standardAgentConfig{
  if os.Geteuid()!=0{
   return errors.New("standard systemd pairing requires root; Agent runs as ssh-manager")
  }
  service,err:=user.Lookup("ssh-manager")
  if err!=nil{return fmt.Errorf("dedicated ssh-manager account missing: %w",err)}
  uid,err=strconv.Atoi(service.Uid);if err!=nil{return err}
  gid,err=strconv.Atoi(service.Gid);if err!=nil{return err}
 }
 if err:=os.MkdirAll(dir,0700);err!=nil{return err}
 st,err:=os.Lstat(dir)
 if err!=nil||!st.IsDir()||st.Mode().Perm()&0022!=0{
  return errors.New("unsafe Agent config directory")
 }
 if path==standardAgentConfig{
  owner,ok:=st.Sys().(*syscall.Stat_t)
  if !ok||owner.Uid!=0{return errors.New("standard Agent config directory must be owned by root")}
  if err=os.Chown(dir,0,gid);err!=nil{return err}
  if err=os.Chmod(dir,0750);err!=nil{return err}
 }
 raw,err:=json.MarshalIndent(c,"","  ")
 if err!=nil{return err}
 f,err:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 removeOnError:=true
 defer func(){if removeOnError{_ = os.Remove(path)}}()
 if _,err=f.Write(raw);err!=nil{_ = f.Close();return err}
 if path==standardAgentConfig{
  if err=f.Chown(uid,gid);err!=nil{_ = f.Close();return err}
 }
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 if err=f.Close();err!=nil{return err}
 parent,err:=os.Open(dir)
 if err!=nil{return err}
 if err=parent.Sync();err!=nil{_ = parent.Close();return err}
 if err=parent.Close();err!=nil{return err}
 removeOnError=false
 return nil
}

// Explicitly reject world/group-readable device keys and symlinked config
// files. The owner must match the executing Agent service identity.
func readAgentConfigBytes(path string)([]byte,error){
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,err}
 f:=os.NewFile(uintptr(fd),path)
 defer f.Close()
 st,err:=f.Stat()
 if err!=nil{return nil,err}
 owner,ok:=st.Sys().(*syscall.Stat_t)
 if !ok||!st.Mode().IsRegular()||st.Mode().Perm()&0077!=0||
  owner.Uid!=uint32(os.Geteuid())||st.Size()>8192{
  return nil,errors.New("Agent device credential file must be a private, same-UID regular file")
 }
 b,err:=io.ReadAll(io.LimitReader(f,8193))
 if err!=nil{return nil,err}
 if len(b)>8192{return nil,errors.New("Agent credential file too large")}
 return b,nil
}

// Ensure no secrets are accidentally written to startup logs.
func describeConfig(c Config)string{
 return strings.TrimRight(c.Gateway,"/")+" / node="+c.NodeID
}

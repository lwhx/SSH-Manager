// Package sshmanaged owns only SSH Manager's own OpenSSH drop-in.
// It never edits sshd_config directly and never automatically rolls back.
package sshmanaged

import (
 "context"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "regexp"
 "strings"
 "syscall"
 "time"

 "github.com/lwhx/SSH-Manager/agent/internal/sshprobe"
)

const ManagedFileName = "00-ssh-manager.conf"
var refRE=regexp.MustCompile("^[a-f0-9]{32}$")
var idRE=regexp.MustCompile("^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$")

type Result struct {
 SnapshotRef string `json:"snapshot_ref"`
 BeforeRevision string `json:"before_revision"`
 AfterRevision string `json:"after_revision"`
 ConfigHash string `json:"config_hash"`
 PasswordAuthentication bool `json:"passwordauthentication"`
 KeyboardInteractive bool `json:"kbdinteractiveauthentication"`
}
type Manifest struct {
 Ref string `json:"ref"`
 NodeID string `json:"node_id"`
 LoginUser string `json:"login_user"`
 MainHash string `json:"main_hash"`
 BeforeRevision string `json:"before_revision"`
 AfterHash string `json:"after_hash"`
 PasswordBefore bool `json:"password_before"`
 KeyboardBefore bool `json:"keyboard_before"`
 CreatedAt int64 `json:"created_at"`
}

// Manager paths and callbacks are fixed by the root daemon; never signed-input controlled.
// Inspect MUST run sshd -t followed by sshd -T -C for the selected connection.
type Manager struct {
 MainPath string
 DropinPath string
 SnapshotDir string
 Inspect func(context.Context)(sshprobe.Effective,error)
 Reload func(context.Context)error
}
func hash(data []byte)string{h:=sha256.Sum256(data);return hex.EncodeToString(h[:])}
func secureMeta(path string,directory bool)(os.FileInfo,error){
 info,err:=os.Lstat(path);if err!=nil{return nil,err}
 if directory&&!info.IsDir()||!directory&&!info.Mode().IsRegular(){
  return nil,errors.New("unsafe SSH managed path type or symbolic link")
 }
 if info.Mode().Perm()&0022!=0{return nil,errors.New("SSH managed path is group/world-writable")}
 stat,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||stat.Uid!=uint32(os.Geteuid()){return nil,errors.New("SSH managed path owner mismatch")}
 return info,nil
}
func safeRead(path string,max int)([]byte,error){
 info,err:=secureMeta(path,false);if err!=nil{return nil,err}
 if info.Size()<0||info.Size()>int64(max){return nil,errors.New("SSH managed file too large")}
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,err}
 f:=os.NewFile(uintptr(fd),path);defer f.Close()
 return io.ReadAll(io.LimitReader(f,int64(max)+1))
}
func syncDir(dir string)error{d,err:=os.Open(dir);if err!=nil{return err};defer d.Close();return d.Sync()}
func writeExclusive(dir,path string,data []byte)error{
 file,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,0600)
 if err!=nil{return err}
 if _,err=file.Write(data);err!=nil{_ = file.Close();return err}
 if err=file.Sync();err!=nil{_ = file.Close();return err}
 if err=file.Close();err!=nil{return err}
 return syncDir(dir)
}
func (m *Manager) paths()(string,[]byte,error){
 if m==nil||m.Inspect==nil||m.Reload==nil||
  filepath.Base(m.DropinPath)!=ManagedFileName||
  !filepath.IsAbs(m.MainPath)||!filepath.IsAbs(m.DropinPath)||
  !filepath.IsAbs(m.SnapshotDir)||
  filepath.Clean(m.MainPath)!=m.MainPath||filepath.Clean(m.DropinPath)!=m.DropinPath||
  filepath.Clean(m.SnapshotDir)!=m.SnapshotDir{
  return "",nil,errors.New("invalid root-managed SSH paths")
 }
 dir:=filepath.Dir(m.DropinPath)
 if _,err:=secureMeta(dir,true);err!=nil{return "",nil,err}
 main,err:=safeRead(m.MainPath,256*1024)
 if err!=nil{return "",nil,err}
 // OpenSSH first-value-wins semantics: the glob MUST be the first
 // effective directive, before system/global settings or Match blocks.
 expected:=filepath.Join(dir,"*.conf")
 found:=false
 for _,line:=range strings.Split(string(main),"\n"){
  fields:=strings.Fields(strings.TrimSpace(line))
  if len(fields)==0||strings.HasPrefix(fields[0],"#"){continue}
  if len(fields)==2&&strings.EqualFold(fields[0],"Include")&&fields[1]==expected{
   found=true
  }
  break
 }
 if !found{return "",nil,errors.New("first sshd_config directive must include the managed drop-in glob")}
 if _,err:=secureMeta(m.SnapshotDir,true);err!=nil{return "",nil,err}
 return dir,main,nil
}
func (m *Manager) readManifest(ref,node,user string)(Manifest,error){
 var value Manifest
 if !refRE.MatchString(ref){return value,errors.New("invalid snapshot reference")}
 data,err:=safeRead(filepath.Join(m.SnapshotDir,ref+".json"),4096)
 if err!=nil{return value,err}
 if err=json.Unmarshal(data,&value);err!=nil{return value,err}
 if value.Ref!=ref||value.NodeID!=node||value.LoginUser!=user||
  !refRE.MatchString(value.Ref)||len(value.MainHash)!=64||len(value.AfterHash)!=64{
  return value,errors.New("snapshot not bound to this node and user")
 }
 return value,nil
}
func (m *Manager) Disable(ctx context.Context,node,user string,before sshprobe.Effective)(Result,error){
 var out Result
 if !idRE.MatchString(node)||user==""{return out,errors.New("invalid node or target user")}
 dir,main,err:=m.paths();if err!=nil{return out,err}
 if _,err=os.Lstat(m.DropinPath);err==nil{
  return out,errors.New("managed drop-in already exists; manual review required")
 }else if !errors.Is(err,os.ErrNotExist){return out,err}
 if !before.PublicKeyAuthentication||(!before.PasswordAuthentication&&!before.KeyboardInteractive){
  return out,errors.New("public key missing or password methods already disabled")
 }
 content:=[]byte("# SSH Manager managed; do not edit while an operation is running\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n")
 random:=make([]byte,16);if _,err=rand.Read(random);err!=nil{return out,err}
 ref:=hex.EncodeToString(random)
 manifest:=Manifest{Ref:ref,NodeID:node,LoginUser:user,MainHash:hash(main),
  BeforeRevision:before.Revision,AfterHash:hash(content),
  PasswordBefore:before.PasswordAuthentication,KeyboardBefore:before.KeyboardInteractive,
  CreatedAt:time.Now().Unix()}
 raw,err:=json.Marshal(manifest);if err!=nil{return out,err}
 // Durable, immutable snapshot record BEFORE any SSH file modification.
 if err=writeExclusive(m.SnapshotDir,filepath.Join(m.SnapshotDir,ref+".json"),raw);err!=nil{return out,err}
 out.SnapshotRef=ref;out.BeforeRevision=before.Revision;out.ConfigHash=manifest.AfterHash
 tmp,err:=os.CreateTemp(dir,".ssh-manager-write-")
 if err!=nil{return out,fmt.Errorf("snapshot exists but drop-in staging failed: %w",err)}
 tmpPath:=tmp.Name()
 defer os.Remove(tmpPath)
 if err=tmp.Chmod(0600);err!=nil{_ = tmp.Close();return out,err}
 if _,err=tmp.Write(content);err!=nil{_ = tmp.Close();return out,err}
 if err=tmp.Sync();err!=nil{_ = tmp.Close();return out,err}
 if err=tmp.Close();err!=nil{return out,err}
 if _,err=os.Lstat(m.DropinPath);err==nil{return out,errors.New("drop-in appeared during staging")}
 if err=os.Rename(tmpPath,m.DropinPath);err!=nil{return out,err}
 if err=syncDir(dir);err!=nil{return out,fmt.Errorf("SSH file written; manual review: %w",err)}
 effective,err:=m.Inspect(ctx)
 if err!=nil{return out,fmt.Errorf("SSH file written but syntax/effective policy unverified; no reload; manual restore needed: %w",err)}
 if effective.PasswordAuthentication||effective.KeyboardInteractive||!effective.PublicKeyAuthentication{
  return out,errors.New("SSH drop-in written but effective password methods not disabled; no reload; manual review")
 }
 if err=m.Reload(ctx);err!=nil{return out,fmt.Errorf("SSH config validated but reload failed; manual review: %w",err)}
 out.AfterRevision=effective.Revision
 out.PasswordAuthentication=effective.PasswordAuthentication
 out.KeyboardInteractive=effective.KeyboardInteractive
 return out,nil
}
func (m *Manager) Restore(ctx context.Context,node,user,ref string,before sshprobe.Effective)(Result,error){
 var out Result
 dir,main,err:=m.paths();if err!=nil{return out,err}
 manifest,err:=m.readManifest(ref,node,user);if err!=nil{return out,err}
 if manifest.MainHash!=hash(main){return out,errors.New("main SSH config changed since snapshot; refuse restoration")}
 data,err:=safeRead(m.DropinPath,4096);if err!=nil{return out,err}
 if hash(data)!=manifest.AfterHash{return out,errors.New("managed drop-in was changed; refuse overwriting administrator edits")}
 out.SnapshotRef=ref;out.BeforeRevision=before.Revision;out.ConfigHash=manifest.MainHash
 // Only an explicit signed MANUAL restore/rollback can remove this file.
 // Never triggered by failed SSH login, Agent disconnection or a timer.
 if err=os.Remove(m.DropinPath);err!=nil{return out,err}
 if err=syncDir(dir);err!=nil{return out,fmt.Errorf("drop-in removed; manual review required: %w",err)}
 effective,err:=m.Inspect(ctx)
 if err!=nil{return out,fmt.Errorf("drop-in removed; SSH config invalid; no reload; manual review: %w",err)}
 if effective.PasswordAuthentication!=manifest.PasswordBefore||
  effective.KeyboardInteractive!=manifest.KeyboardBefore{
  return out,errors.New("original password policy did not return; no reload; manual review")
 }
 if err=m.Reload(ctx);err!=nil{return out,fmt.Errorf("original policy checked but reload failed; manual review: %w",err)}
 out.AfterRevision=effective.Revision
 out.PasswordAuthentication=effective.PasswordAuthentication
 out.KeyboardInteractive=effective.KeyboardInteractive
 return out,nil
}
func ReloadSystemSSH(ctx context.Context)error{
 for _,service:=range []string{"ssh.service","sshd.service"}{
  c,cancel:=context.WithTimeout(ctx,8*time.Second)
  err:=exec.CommandContext(c,"/usr/bin/systemctl","reload",service).Run()
  cancel()
  if err==nil{return nil}
 }
 return errors.New("no supported SSH service accepted reload; manual review required")
}

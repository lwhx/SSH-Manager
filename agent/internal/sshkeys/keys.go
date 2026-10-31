// Package sshkeys contains conservative, local-only authorized_keys file operations.
// It does not open network sockets, disable password authentication or remove keys.
package sshkeys

import (
 "bytes"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "syscall"
)

const maxAuthKeysSize = 4 << 20

type Result struct {
 Fingerprint string `json:"key_fingerprint"`
 FileChecked bool `json:"file_checked"`
 AlreadyPresent bool `json:"already_present"`
 SnapshotRef string `json:"snapshot_ref,omitempty"`
 BeforeSHA256 string `json:"before_sha256,omitempty"`
 AfterSHA256 string `json:"after_sha256,omitempty"`
}

func NormalizeED25519(value string)(string,string,error){
 if strings.ContainsAny(value,"\r\n\x00"){return "","",errors.New("multiline public key rejected")}
 parts:=strings.Fields(value)
 if len(parts)<2||parts[0]!="ssh-ed25519"{return "","",errors.New("only plain ssh-ed25519 public keys are accepted")}
 raw,err:=base64.StdEncoding.Strict().DecodeString(parts[1])
 if err!=nil||len(raw)!=51{return "","",errors.New("invalid Ed25519 SSH blob")}
 if binary.BigEndian.Uint32(raw[:4])!=11||string(raw[4:15])!="ssh-ed25519"||binary.BigEndian.Uint32(raw[15:19])!=32{
  return "","",errors.New("malformed Ed25519 SSH blob")
 }
 digest:=sha256.Sum256(raw)
 fp:="SHA256:"+base64.RawStdEncoding.EncodeToString(digest[:])
 return "ssh-ed25519 "+base64.StdEncoding.EncodeToString(raw),fp,nil
}

func checkedDir(fd int, uid int)error{
 var stat syscall.Stat_t
 if err:=syscall.Fstat(fd,&stat);err!=nil{return err}
 if stat.Mode&syscall.S_IFMT!=syscall.S_IFDIR{return errors.New("expected directory")}
 if stat.Uid!=uint32(uid)&&stat.Uid!=0{return errors.New("untrusted directory owner")}
 if stat.Mode&0022!=0{return errors.New("directory writable by group or others")}
 return nil
}

// openHome verifies every component from the root directory with O_NOFOLLOW.
// Merely using O_NOFOLLOW on the final home segment would still allow a
// symlink in an ancestor to redirect privileged key writes.
func openHome(home string,uid int)(int,error){
 fd,err:=syscall.Open("/",syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return -1,err}
 if err=checkedDir(fd,uid);err!=nil{syscall.Close(fd);return -1,err}
 parts:=strings.Split(strings.TrimPrefix(home,"/"),"/")
 for index,name:=range parts{
  if name==""||name=="."||name==".."{syscall.Close(fd);return -1,errors.New("unsafe home component")}
  next,err:=syscall.Openat(fd,name,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
  syscall.Close(fd)
  if err!=nil{return -1,fmt.Errorf("open home component: %w",err)}
  // A root-owned sticky ancestor (such as /tmp in isolated tests) cannot
  // be replaced by other users; each openat still rejects symlink traversal.
  // The final user's home itself must always pass strict ownership/mode checks.
  if err=checkedDir(next,uid);err!=nil{
   var st syscall.Stat_t
   stickyRoot:=syscall.Fstat(next,&st)==nil&&st.Uid==0&&st.Mode&syscall.S_ISVTX!=0&&st.Mode&syscall.S_IFMT==syscall.S_IFDIR
   if !stickyRoot||index==len(parts)-1{
    syscall.Close(next)
    return -1,fmt.Errorf("unsafe home component: %w",err)
   }
  }
  fd=next
 }
 return fd,nil
}

func maybeChown(fd,uid,gid int)error{
 var st syscall.Stat_t
 if err:=syscall.Fstat(fd,&st);err!=nil{return err}
 if st.Uid==uint32(uid)&&st.Gid==uint32(gid){return nil}
 if os.Geteuid()!=0{return errors.New("cannot set target user ownership without root")}
 return syscall.Fchown(fd,uid,gid)
}

// InstallDaily appends exactly one validated key to the default
// ~/.ssh/authorized_keys. The caller MUST first confirm sshd -T reports
// that exact path as effective, check target user, and verify signed command.
// No caller should expose this function as a generic file-write API.
func InstallDaily(home string,uid,gid int,publicKey,snapshotDir string)(Result,error){
 return InstallManaged(home,uid,gid,publicKey,snapshotDir,"daily")
}
func InstallRescue(home string,uid,gid int,publicKey,snapshotDir string)(Result,error){
 return InstallManaged(home,uid,gid,publicKey,snapshotDir,"rescue")
}
// InstallManaged only appends one precisely labelled SSH Manager public key.
// The rescue key is never installed just because it exists in Cloudflare.
func InstallManaged(home string,uid,gid int,publicKey,snapshotDir,purpose string)(Result,error){
 var result Result
 if purpose!="daily"&&purpose!="rescue"{return result,errors.New("unsupported managed key purpose")}
 normalized,fingerprint,err:=NormalizeED25519(publicKey)
 if err!=nil{return result,err}
 result.Fingerprint=fingerprint
 if !filepath.IsAbs(home)||filepath.Clean(home)!=home||home=="/"{return result,errors.New("unsafe home path")}
 if !filepath.IsAbs(snapshotDir){return result,errors.New("snapshot directory must be absolute")}
 homeFD,err:=openHome(home,uid)
 if err!=nil{return result,fmt.Errorf("open home: %w",err)}
 defer syscall.Close(homeFD)
 if err=checkedDir(homeFD,uid);err!=nil{return result,fmt.Errorf("home validation: %w",err)}

 sshDirFD,err:=syscall.Openat(homeFD,".ssh",syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if errors.Is(err,syscall.ENOENT){
  if err=syscall.Mkdirat(homeFD,".ssh",0700);err!=nil{return result,fmt.Errorf("create .ssh: %w",err)}
  sshDirFD,err=syscall.Openat(homeFD,".ssh",syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
  if err==nil{err=maybeChown(sshDirFD,uid,gid)}
 }
 if err!=nil{return result,fmt.Errorf("open .ssh: %w",err)}
 defer syscall.Close(sshDirFD)
 if err=checkedDir(sshDirFD,uid);err!=nil{return result,fmt.Errorf(".ssh validation: %w",err)}

 fd,err:=syscall.Openat(sshDirFD,"authorized_keys",syscall.O_RDWR|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 created:=false
 if errors.Is(err,syscall.ENOENT){
  fd,err=syscall.Openat(sshDirFD,"authorized_keys",syscall.O_RDWR|syscall.O_APPEND|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0600)
  if err==nil{created=true}
 }
 if err!=nil{return result,fmt.Errorf("open authorized_keys: %w",err)}
 f:=os.NewFile(uintptr(fd),"authorized_keys")
 defer f.Close()
 if err=syscall.Flock(fd,syscall.LOCK_EX);err!=nil{return result,err}
 defer syscall.Flock(fd,syscall.LOCK_UN)
 if created{
  if err=maybeChown(fd,uid,gid);err!=nil{return result,err}
 }
 var stat syscall.Stat_t
 if err=syscall.Fstat(fd,&stat);err!=nil{return result,err}
 if stat.Mode&syscall.S_IFMT!=syscall.S_IFREG{return result,errors.New("authorized_keys is not a regular file")}
 if stat.Uid!=uint32(uid)&&stat.Uid!=0{return result,errors.New("unsafe authorized_keys owner")}
 if stat.Mode&0022!=0{return result,errors.New("authorized_keys writable by group or others")}
 if stat.Size>maxAuthKeysSize{return result,errors.New("authorized_keys too large")}
 if _,err=f.Seek(0,io.SeekStart);err!=nil{return result,err}
 before,err:=io.ReadAll(io.LimitReader(f,maxAuthKeysSize+1))
 if err!=nil||len(before)>maxAuthKeysSize{return result,errors.New("authorized_keys read limit exceeded")}
 checksum:=sha256.Sum256(before);result.BeforeSHA256=hex.EncodeToString(checksum[:])

 // Respect existing restrictions on an identical public key. Never add a
 // second unrestricted line if the user already restricted the same key.
 blob:=strings.Fields(normalized)[1]
 for _,line:=range bytes.Split(before,[]byte("\n")){
  words:=strings.Fields(strings.TrimSpace(string(line)))
  for i:=0;i+1<len(words);i++{
   if words[i]!="ssh-ed25519"||words[i+1]!=blob{continue}
   if i!=0{return result,errors.New("matching key has existing restrictions; refusing to broaden access")}
   result.AlreadyPresent=true;result.FileChecked=true;result.AfterSHA256=result.BeforeSHA256
   return result,nil
  }
 }

 // Fail closed when the snapshot cannot be created. Snapshot contents are
 // SSH PUBLIC keys only, but must still be root-private in production.
 ref,err:=snapshotAuthorizedKeys(snapshotDir,before,stat,created)
 if err!=nil{return result,err}
 result.SnapshotRef=ref
 suffix:=""
 if len(before)>0&&before[len(before)-1]!='\n'{suffix="\n"}
 data:=[]byte(suffix+normalized+" ssh-manager-"+purpose+"\n")
 n,err:=f.Write(data)
 if err!=nil||n!=len(data){return result,fmt.Errorf("authorized_keys partial append (%d/%d): %w",n,len(data),err)}
 if err=f.Sync();err!=nil{return result,err}
 checksum=sha256.Sum256(append(before,data...))
 result.AfterSHA256=hex.EncodeToString(checksum[:])
 result.FileChecked=true
 return result,nil
}

func snapshotAuthorizedKeys(dir string,prior []byte,stat syscall.Stat_t,created bool)(string,error){
 if err:=os.MkdirAll(dir,0700);err!=nil{return "",err}
 info,err:=os.Lstat(dir)
 if err!=nil||!info.IsDir()||info.Mode().Perm()&0077!=0{return "",errors.New("snapshot directory must be private and not a symlink")}
 if owner,ok:=info.Sys().(*syscall.Stat_t);!ok||owner.Uid!=uint32(os.Geteuid()){
  return "",errors.New("snapshot directory must be owned by the helper")
 }
 random:=make([]byte,16)
 if _,err=rand.Read(random);err!=nil{return "",err}
 id:=hex.EncodeToString(random)
 path:=filepath.Join(dir,id+".authorized_keys")
 f,err:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return "",err}
 if _,err=f.Write(prior);err!=nil{_ = f.Close();return "",err}
 if err=f.Sync();err!=nil{_ = f.Close();return "",err}
 if err=f.Close();err!=nil{return "",err}
 metadata,_:=json.Marshal(map[string]any{
  "original_existed":!created,"original_mode":stat.Mode&0777,
  "original_uid":stat.Uid,"original_gid":stat.Gid,"sha256":fmt.Sprintf("%x",sha256.Sum256(prior)),
 })
 metaFile,err:=os.OpenFile(filepath.Join(dir,id+".json"),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return "",err}
 if _,err=metaFile.Write(metadata);err!=nil{_ = metaFile.Close();return "",err}
 if err=metaFile.Sync();err!=nil{_ = metaFile.Close();return "",err}
 if err=metaFile.Close();err!=nil{return "",err}
 d,err:=os.Open(dir);if err!=nil{return "",err}
 defer d.Close()
 if err=d.Sync();err!=nil{return "",err}
 return id,nil
}

// RevokeRescue only deletes an EXACT ssh-manager-rescue line for this public
// key; it never deletes arbitrary authorized_keys entries or all rescue keys.
// Snapshot is durable before a same-directory atomic file replacement.
func RevokeRescue(home string,uid,gid int,publicKey,snapshotDir string)(Result,error){
 var result Result
 normalized,fingerprint,err:=NormalizeED25519(publicKey)
 if err!=nil{return result,err}
 result.Fingerprint=fingerprint
 if !filepath.IsAbs(home)||filepath.Clean(home)!=home||home=="/"||
  !filepath.IsAbs(snapshotDir){return result,errors.New("unsafe rescue revoke paths")}
 homeFD,err:=openHome(home,uid)
 if err!=nil{return result,err}
 defer syscall.Close(homeFD)
 if err=checkedDir(homeFD,uid);err!=nil{return result,err}
 sshFD,err:=syscall.Openat(homeFD,".ssh",syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return result,err}
 defer syscall.Close(sshFD)
 if err=checkedDir(sshFD,uid);err!=nil{return result,err}
 fd,err:=syscall.Openat(sshFD,"authorized_keys",syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return result,err}
 f:=os.NewFile(uintptr(fd),"authorized_keys")
 defer f.Close()
 if err=syscall.Flock(fd,syscall.LOCK_EX);err!=nil{return result,err}
 defer syscall.Flock(fd,syscall.LOCK_UN)
 var st syscall.Stat_t
 if err=syscall.Fstat(fd,&st);err!=nil{return result,err}
 if st.Mode&syscall.S_IFMT!=syscall.S_IFREG||
  (st.Uid!=uint32(uid)&&st.Uid!=0)||st.Mode&0022!=0||st.Size>maxAuthKeysSize{
  return result,errors.New("unsafe authorized_keys for rescue revoke")
 }
 before,err:=io.ReadAll(io.LimitReader(f,maxAuthKeysSize+1))
 if err!=nil||len(before)>maxAuthKeysSize{return result,errors.New("authorized_keys read limit exceeded")}
 beforeSum:=sha256.Sum256(before)
 result.BeforeSHA256=hex.EncodeToString(beforeSum[:])
 target:=[]byte(normalized+" ssh-manager-rescue")
 lines:=bytes.SplitAfter(before,[]byte("\n"))
 var after []byte
 found:=0
 for _,line:=range lines{
  if bytes.Equal(bytes.TrimSuffix(line,[]byte("\n")),target){
   found++
   continue
  }
  after=append(after,line...)
 }
 if found!=1{return result,errors.New("expected exactly one SSH Manager rescue key line")}
 ref,err:=snapshotAuthorizedKeys(snapshotDir,before,st,false)
 if err!=nil{return result,err}
 result.SnapshotRef=ref
 random:=make([]byte,16);if _,err=rand.Read(random);err!=nil{return result,err}
 tmpName:=".ssh-manager-revoke-"+hex.EncodeToString(random)
 tmpFD,err:=syscall.Openat(sshFD,tmpName,syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0600)
 if err!=nil{return result,err}
 defer syscall.Unlinkat(sshFD,tmpName)
 tmp:=os.NewFile(uintptr(tmpFD),tmpName)
 if err=maybeChown(tmpFD,uid,gid);err!=nil{_ = tmp.Close();return result,err}
 if err=tmp.Chmod(os.FileMode(st.Mode&0777));err!=nil{_ = tmp.Close();return result,err}
 n,err:=tmp.Write(after)
 if err!=nil||n!=len(after){_ = tmp.Close();return result,errors.New("rescue revoke temp write incomplete")}
 if err=tmp.Sync();err!=nil{_ = tmp.Close();return result,err}
 if err=tmp.Close();err!=nil{return result,err}
 // Reject a replacement of the original file before our atomic rename.
 checkFD,err:=syscall.Openat(sshFD,"authorized_keys",syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return result,err}
 var check syscall.Stat_t
 err=syscall.Fstat(checkFD,&check);syscall.Close(checkFD)
 if err!=nil||check.Ino!=st.Ino||check.Dev!=st.Dev||check.Size!=st.Size{
  return result,errors.New("authorized_keys changed during rescue revocation")
 }
 if err=syscall.Renameat(sshFD,tmpName,sshFD,"authorized_keys");err!=nil{return result,err}
 if err=syscall.Fsync(sshFD);err!=nil{return result,err}
 checksum:=sha256.Sum256(after)
 result.AfterSHA256=hex.EncodeToString(checksum[:])
 result.FileChecked=true
 return result,nil
}

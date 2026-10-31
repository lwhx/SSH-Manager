package sshhelper

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "syscall"
 "time"
)

// PreparedChallenge is an explicitly signed request to record a future login
// proof attempt; recording it has NO effect on authorized_keys or sshd config.
type PreparedChallenge struct {
 VerificationID string `json:"verification_id"`
 NonceHash string `json:"nonce_hash"`
 LoginUser string `json:"login_user"`
 Fingerprint string `json:"fingerprint"`
 KeyID string `json:"key_id"`
 ConfigRevision string `json:"config_revision"`
 IssuedAt int64 `json:"issued_at"`
 ExpiresAt int64 `json:"expires_at"`
}
var keyFingerprintRE=regexp.MustCompile("^SHA256:[A-Za-z0-9+/]{43}$")
var hexHashRE=regexp.MustCompile("^[a-f0-9]{64}$")

func (p PreparedChallenge)Validate(nodeUser,revision string,now time.Time)error{
 if !uuidRE.MatchString(p.VerificationID)||!uuidRE.MatchString(p.KeyID)||
  !hexHashRE.MatchString(p.NonceHash)||!keyFingerprintRE.MatchString(p.Fingerprint){
  return errors.New("invalid verification identity or digest")
 }
 if !accountRE.MatchString(p.LoginUser)||p.LoginUser!=nodeUser||
  p.ConfigRevision!=revision||!hexHashRE.MatchString(p.ConfigRevision){
  return errors.New("verification user or SSH config revision mismatch")
 }
 t:=now.Unix()
 if p.IssuedAt>t+10||p.ExpiresAt<=t||p.ExpiresAt<=p.IssuedAt||
  p.ExpiresAt-p.IssuedAt>300{
  return errors.New("verification challenge expired or longer than five minutes")
 }
 return nil
}
type ChallengeStore struct{ Directory string }
func (s *ChallengeStore)Save(p PreparedChallenge)error{
 if s==nil||!uuidRE.MatchString(p.VerificationID){return errors.New("invalid challenge store")}
 if !filepath.IsAbs(s.Directory)||filepath.Clean(s.Directory)!=s.Directory{
  return errors.New("unsafe challenge store path")
 }
 if err:=os.MkdirAll(s.Directory,0700);err!=nil{return err}
 info,err:=os.Lstat(s.Directory)
 if err!=nil||!info.IsDir()||info.Mode().Perm()&0077!=0{return errors.New("unsafe local challenge directory")}
 uid,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||uid.Uid!=uint32(os.Geteuid()){
  return errors.New("local challenge store ownership mismatch")
 }
 destination:=filepath.Join(s.Directory,p.VerificationID+".json")
 file,err:=os.OpenFile(destination,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if errors.Is(err,os.ErrExist){return errors.New("verification already prepared")}
 if err!=nil{return err}
 data,err:=json.Marshal(p)
 if err!=nil{_ = file.Close();return err}
 if _,err=file.Write(data);err!=nil{_ = file.Close();return err}
 if err=file.Sync();err!=nil{_ = file.Close();return err}
 if err=file.Close();err!=nil{return err}
 d,err:=os.Open(s.Directory);if err!=nil{return err}
 defer d.Close()
 if err=d.Sync();err!=nil{return fmt.Errorf("persist challenge directory: %w",err)}
 return nil
}
func (s *ChallengeStore)Read(id string)(PreparedChallenge,error){
 var p PreparedChallenge
 if s==nil||!uuidRE.MatchString(id){return p,errors.New("invalid challenge ID")}
 path:=filepath.Join(s.Directory,id+".json")
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return p,err}
 f:=os.NewFile(uintptr(fd),path);defer f.Close()
 stat,err:=f.Stat()
 if err!=nil||!stat.Mode().IsRegular()||stat.Mode().Perm()&0077!=0||
  stat.Size()>4096{
  return p,errors.New("unsafe local challenge file")
 }
 owner,ok:=stat.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=uint32(os.Geteuid()){
  return p,errors.New("local challenge file ownership mismatch")
 }
 data,err:=io.ReadAll(io.LimitReader(f,4097))
 if err!=nil||len(data)>4096{return p,errors.New("invalid challenge file read")}
 if err=json.Unmarshal(data,&p);err!=nil{return p,err}
 if p.VerificationID!=id{return PreparedChallenge{},errors.New("challenge storage mismatch")}
 return p,nil
}
func (p PreparedChallenge)HashSummary()string{
 h:=sha256.Sum256([]byte(p.VerificationID+"|"+p.NonceHash+"|"+p.ConfigRevision))
 return hex.EncodeToString(h[:])
}

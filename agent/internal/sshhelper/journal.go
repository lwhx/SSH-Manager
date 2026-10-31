package sshhelper

import (
 "encoding/json"
 "errors"
 "io"
 "os"
 "path/filepath"
 "syscall"
 "time"
)

const maxJournalResultBytes=8192

type Journal struct{Directory string}

type journalClaim struct{
 OperationID string `json:"operation_id"`
 NodeID string `json:"node_id"`
 Action string `json:"action"`
 ReservedAt string `json:"reserved_at"`
}
type journalOutcome struct{
 OperationID string `json:"operation_id"`
 NodeID string `json:"node_id"`
 Action string `json:"action"`
 Result Result `json:"result"`
}
type JournalRecovery struct{
 State string `json:"state"`
 Result Result `json:"result,omitempty"`
}
func allowedJournalAction(action string)bool{
 switch action{
 case "ssh.daily.install","ssh.policy.inspect","ssh.verification.prepare",
  "ssh.password.disable","ssh.password.restore","ssh.config.rollback",
  "ssh.rescue.enable","ssh.rescue.revoke":
  return true
 default:return false
 }
}
func (j *Journal)validatedDir()(string,error){
 if j==nil||!filepath.IsAbs(j.Directory)||filepath.Clean(j.Directory)!=j.Directory||
  j.Directory=="/"{return "",errors.New("invalid root journal directory")}
 if err:=os.MkdirAll(j.Directory,0700);err!=nil{return "",err}
 st,err:=os.Lstat(j.Directory)
 if err!=nil||!st.IsDir()||st.Mode().Perm()&0077!=0{
  return "",errors.New("unsafe root journal permissions")
 }
 owner,ok:=st.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=uint32(os.Geteuid()){
  return "",errors.New("root journal ownership mismatch")
 }
 return j.Directory,nil
}
func durableWriteExclusive(dir,filename string,data []byte)error{
 f,err:=os.OpenFile(filepath.Join(dir,filename),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 if _,err=f.Write(data);err!=nil{_ = f.Close();return err}
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 if err=f.Close();err!=nil{return err}
 d,err:=os.Open(dir);if err!=nil{return err}
 defer d.Close()
 return d.Sync()
}
func readPrivateJournalFile(path string)([]byte,error){
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,err}
 f:=os.NewFile(uintptr(fd),path);defer f.Close()
 st,err:=f.Stat()
 if err!=nil||!st.Mode().IsRegular()||st.Size()>maxJournalResultBytes||
  st.Mode().Perm()&0077!=0{return nil,errors.New("unsafe root operation journal file")}
 owner,ok:=st.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=uint32(os.Geteuid()){
  return nil,errors.New("untrusted root operation journal owner")
 }
 data,err:=io.ReadAll(io.LimitReader(f,maxJournalResultBytes+1))
 if err!=nil||len(data)>maxJournalResultBytes{
  return nil,errors.New("invalid root operation journal read")
 }
 return data,nil
}
func (j *Journal)Claim(id,nodeID,action string)error{
 if !uuidRE.MatchString(id)||!uuidRE.MatchString(nodeID)||!allowedJournalAction(action){
  return errors.New("invalid root operation reservation scope")
 }
 dir,err:=j.validatedDir();if err!=nil{return err}
 raw,err:=json.Marshal(journalClaim{
  OperationID:id,NodeID:nodeID,Action:action,
  ReservedAt:time.Now().UTC().Format(time.RFC3339Nano),
 })
 if err!=nil{return err}
 if err=durableWriteExclusive(dir,id+".json",raw);err!=nil{
  if errors.Is(err,os.ErrExist){return errors.New("replayed signed root operation")}
  return err
 }
 return nil
}
// Finalize persists the exact terminal result BEFORE Root Helper responds.
// No recovery path is permitted to re-execute a claimed signed operation.
func(j *Journal)Finalize(id,nodeID,action string,result Result)error{
 if !uuidRE.MatchString(id)||!uuidRE.MatchString(nodeID)||!allowedJournalAction(action)||
  result.Code==""||len(result.Code)>64{
  return errors.New("invalid root journal final result")
 }
 dir,err:=j.validatedDir();if err!=nil{return err}
 claim,err:=j.readClaim(dir,id)
 if err!=nil{return err}
 if claim.NodeID!=nodeID||claim.Action!=action{return errors.New("root journal claim scope mismatch")}
 payload,err:=json.Marshal(journalOutcome{
  OperationID:id,NodeID:nodeID,Action:action,Result:result,
 })
 if err!=nil||len(payload)>maxJournalResultBytes{
  return errors.New("root operation result exceeds persistence limit")
 }
 return durableWriteExclusive(dir,id+".result.json",payload)
}
func(j *Journal)readClaim(dir,id string)(journalClaim,error){
 var entry journalClaim
 raw,err:=readPrivateJournalFile(filepath.Join(dir,id+".json"))
 if err!=nil{return entry,err}
 if err=json.Unmarshal(raw,&entry);err!=nil{return entry,err}
 if entry.OperationID!=id||!uuidRE.MatchString(entry.NodeID)||
  !allowedJournalAction(entry.Action){
  return entry,errors.New("root journal claim lacks verified node and action")
 }
 return entry,nil
}
// Recover returns RECORDED only when BOTH the root-owned reservation and
// matching durable result exist. An unfinished reservation is UNCONFIRMED:
// a shell/Agent must NEVER assume whether an SSH write did or did not happen.
func (j *Journal)Recover(id,nodeID,action string)(JournalRecovery,error){
 var output JournalRecovery
 if !uuidRE.MatchString(id)||!uuidRE.MatchString(nodeID)||!allowedJournalAction(action){
  return output,errors.New("invalid root journal recovery scope")
 }
 dir,err:=j.validatedDir();if err!=nil{return output,err}
 claim,err:=j.readClaim(dir,id)
 if errors.Is(err,os.ErrNotExist){
  return JournalRecovery{State:"NOT_FOUND"},nil
 }
 if err!=nil{return output,err}
 if claim.NodeID!=nodeID||claim.Action!=action{
  return output,errors.New("requested recovery scope differs from signed reservation")
 }
 raw,err:=readPrivateJournalFile(filepath.Join(dir,id+".result.json"))
 if errors.Is(err,os.ErrNotExist){
  return JournalRecovery{State:"UNCONFIRMED"},nil
 }
 if err!=nil{return output,err}
 var outcome journalOutcome
 if err=json.Unmarshal(raw,&outcome);err!=nil{return output,err}
 if outcome.OperationID!=id||outcome.NodeID!=nodeID||outcome.Action!=action||
  outcome.Result.Code==""||len(outcome.Result.Code)>64{
  return output,errors.New("root journal result does not match reservation")
 }
 return JournalRecovery{State:"RECORDED",Result:outcome.Result},nil
}

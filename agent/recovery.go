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
 "path/filepath"
 "strings"
 "syscall"
 "time"
)

const helperJournalSocket="/run/ssh-manager/helper.sock"
const maxRecoveryReceiptBytes=4096

type claimedOperation struct{
 OperationID string `json:"operation_id"`
 NodeID string `json:"node_id"`
 Action string `json:"action"`
 IssuedAt int64 `json:"issued_at"`
}
type rootRecovery struct{
 State string `json:"state"`
 Result LocalHelperResult `json:"result"`
}
func rootRecoveryAction(action string)bool{
 switch action{
 case "ssh.policy.inspect","ssh.daily.install","ssh.verification.prepare":
  return true
 default:return false
 }
}
func(a *Agent)operationReceiptsDir()(string,error){
 base:=a.config.StateDir
 if base==""{base=defaultAgentStateDir}
 if !filepath.IsAbs(base)||filepath.Clean(base)!=base||base=="/"{
  return "",errors.New("unsafe Agent receipt state directory")
 }
 dir:=filepath.Join(base,"operations")
 if err:=os.MkdirAll(dir,0700);err!=nil{return "",err}
 info,err:=os.Lstat(dir)
 if err!=nil||!info.IsDir()||info.Mode().Perm()&0077!=0{
  return "",errors.New("unsafe Agent operation receipt directory")
 }
 owner,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=uint32(os.Geteuid()){
  return "",errors.New("Agent operation receipt owner mismatch")
 }
 return dir,nil
}
func readClaimedOperation(path string)(claimedOperation,error){
 var receipt claimedOperation
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return receipt,err}
 f:=os.NewFile(uintptr(fd),path);defer f.Close()
 info,err:=f.Stat()
 if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()&0077!=0||
  info.Size()>maxRecoveryReceiptBytes{
  return receipt,errors.New("unsafe Agent operation receipt")
 }
 owner,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=uint32(os.Geteuid()){
  return receipt,errors.New("Agent operation receipt UID mismatch")
 }
 raw,err:=io.ReadAll(io.LimitReader(f,maxRecoveryReceiptBytes+1))
 if err!=nil||len(raw)>maxRecoveryReceiptBytes{return receipt,errors.New("unsafe receipt size")}
 if err=json.Unmarshal(raw,&receipt);err!=nil{return receipt,err}
 if !operationID.MatchString(receipt.OperationID)||!operationID.MatchString(receipt.NodeID)||
  receipt.IssuedAt<0{
  return receipt,errors.New("malformed claimed operation identity")
 }
 return receipt,nil
}
func fileExistsSafely(path string)(bool,error){
 info,err:=os.Lstat(path)
 if errors.Is(err,os.ErrNotExist){return false,nil}
 if err!=nil{return false,err}
 owner,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||!info.Mode().IsRegular()||info.Mode().Perm()&0077!=0||
  owner.Uid!=uint32(os.Geteuid()){
  return false,errors.New("untrusted recovery marker or pending report")
 }
 return true,nil
}
func(a *Agent)markOperationSettled(id string)error{
 if !operationID.MatchString(id){return errors.New("invalid operation settlement ID")}
 dir,err:=a.operationReceiptsDir();if err!=nil{return err}
 receipt:=filepath.Join(dir,id+".json")
 if _,err=os.Lstat(receipt);errors.Is(err,os.ErrNotExist){
  // Standalone test/report migration may lack a legacy receipt.
  return nil
 }else if err!=nil{return err}
 if _,err=readClaimedOperation(receipt);err!=nil{return err}
 marker:=filepath.Join(dir,id+".settled")
 f,err:=os.OpenFile(marker,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if errors.Is(err,os.ErrExist){
  _,verifiedErr:=fileExistsSafely(marker)
  return verifiedErr
 }
 if err!=nil{return err}
 if _,err=f.WriteString("cloud-terminal-report-confirmed\n");err!=nil{_ = f.Close();return err}
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 if err=f.Close();err!=nil{return err}
 d,err:=os.Open(dir);if err!=nil{return err}
 defer d.Close();return d.Sync()
}
func(a *Agent)markManualReview(id,state string)error{
 if !operationID.MatchString(id){return errors.New("invalid manual review ID")}
 if state!="NOT_FOUND"&&state!="UNCONFIRMED"{
  return errors.New("untrusted manual review state")
 }
 dir,err:=a.operationReceiptsDir();if err!=nil{return err}
 path:=filepath.Join(dir,id+".review")
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if errors.Is(err,os.ErrExist){return nil}
 if err!=nil{return err}
 if _,err=f.WriteString(state+"\n");err!=nil{_ = f.Close();return err}
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 if err=f.Close();err!=nil{return err}
 d,err:=os.Open(dir);if err!=nil{return err}
 defer d.Close();return d.Sync()
}
// readRootOutcome only asks Root Helper for its root-owned durable result.
// It never retransmits a signed SSH command or relies on a client claim
// that a privileged operation completed.
func(a *Agent)readRootOutcome(ctx context.Context,id,action string,socket string)(rootRecovery,error){
 var recovery rootRecovery
 if !operationID.MatchString(id)||!rootRecoveryAction(action){
  return recovery,errors.New("unsafe Root journal recovery request")
 }
 scope,cancel:=context.WithTimeout(ctx,6*time.Second);defer cancel()
 conn,err:=(&net.Dialer{}).DialContext(scope,"unix",socket)
 if err!=nil{return recovery,err}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(6*time.Second))
 request,_:=json.Marshal(map[string]string{
  "local_action":"operation.recover","operation_id":id,"action":action,
 })
 if _,err=conn.Write(request);err!=nil{return recovery,err}
 if socket,ok:=conn.(*net.UnixConn);ok{
  if err=socket.CloseWrite();err!=nil{return recovery,err}
 }
 raw,err:=io.ReadAll(io.LimitReader(conn,8193))
 if err!=nil||len(raw)>8192{return recovery,errors.New("invalid Root recovery response size")}
 if err=json.Unmarshal(raw,&recovery);err!=nil{return recovery,err}
 switch recovery.State{
 case "RECORDED":
  if recovery.Result.Code==""||len(recovery.Result.Code)>64{
   return recovery,errors.New("durable Root operation outcome missing code")
  }
 case "NOT_FOUND","UNCONFIRMED":
 default:return recovery,errors.New("unrecognized Root operation recovery state")
 }
 return recovery,nil
}
func (a *Agent)recoverClaimedOperations(ctx context.Context){
 if a.config.HelperSocket!=helperJournalSocket{
  log.Print("Root Helper recovery unavailable: nonstandard socket");return
 }
 a.recoverClaimedOperationsWithSocket(ctx,helperJournalSocket)
}
func (a *Agent)recoverClaimedOperationsWithSocket(ctx context.Context,socket string){
 dir,err:=a.operationReceiptsDir()
 if err!=nil{log.Printf("Agent claimed-operation recovery cannot scan: %v",err);return}
 receipts,err:=os.ReadDir(dir)
 if err!=nil{log.Printf("claimed-operation recovery failed: %v",err);return}
 reportDir,err:=a.operationReportDir()
 if err!=nil{log.Printf("claimed-operation recovery report directory invalid: %v",err);return}
 lookups:=0
 for _,entry:=range receipts{
  if ctx.Err()!=nil||lookups>=4{return}
  if entry.IsDir()||!strings.HasSuffix(entry.Name(),".json"){continue}
  id:=strings.TrimSuffix(entry.Name(),".json")
  if !operationID.MatchString(id){continue}
  receipt,err:=readClaimedOperation(filepath.Join(dir,entry.Name()))
  if err!=nil||receipt.OperationID!=id||receipt.NodeID!=a.config.NodeID{
   log.Printf("claimed operation %s needs operator inspection: invalid local receipt",id)
   continue
  }
  if !rootRecoveryAction(receipt.Action){continue}
  skip:=false
  for _,path:=range []string{
   filepath.Join(dir,id+".settled"),
   filepath.Join(dir,id+".review"),
   filepath.Join(reportDir,id+".json"),
   filepath.Join(reportDir,"rejected",id+".json"),
  }{
   exists,err:=fileExistsSafely(path)
   if err!=nil{
    log.Printf("unsafe recovery state for %s: %v",id,err)
    skip=true;break
   }
   if exists{skip=true;break}
  }
  if skip{continue}
  lookups++
  outcome,err:=a.readRootOutcome(ctx,id,receipt.Action,socket)
  if err!=nil{
   log.Printf("Root journal recovery for %s unavailable: %v",id,err)
   continue
  }
  switch outcome.State{
  case "RECORDED":
   status:="FAILED"
   if outcome.Result.OK{status="SUCCEEDED"}
   if err:=a.enqueueOperationReport(id,status,outcome.Result.Code,outcome.Result.Detail);err!=nil{
    log.Printf("cannot persist recovered Root result %s: %v",id,err)
    continue
   }
   log.Printf("recovered durable Root result for %s; no SSH action re-executed",id)
  case "NOT_FOUND","UNCONFIRMED":
   // A transient on-going Root operation may still finish. After the
   // maximum signed-command TTL plus grace, stop automatic recovery and
   // leave an explicit manual-review marker. No optimistic FAILED or
   // SUCCEEDED report is ever fabricated from a reservation alone.
   if receipt.IssuedAt>0&&time.Now().Unix()-receipt.IssuedAt>=120{
    if err=a.markManualReview(id,outcome.State);err!=nil{
     log.Printf("cannot record manual-review state for %s: %v",id,err)
    }else{
     log.Printf("Root operation %s outcome %s: manual investigation required",id,outcome.State)
    }
   }
  }
 }
}
func (a *Agent)recoverSingleRootOperation(ctx context.Context,id,action string){
 if a.config.HelperSocket!=helperJournalSocket{return}
 out,err:=a.readRootOutcome(ctx,id,action,a.config.HelperSocket)
 if err!=nil{
  log.Printf("Root operation %s response unavailable: %v",id,err)
  return
 }
 if out.State!="RECORDED"{
  log.Printf("Root operation %s outcome %s: will not assume failure or retry SSH write",id,out.State)
  return
 }
 status:="FAILED"
 if out.Result.OK{status="SUCCEEDED"}
 report(a,ctx,id,status,out.Result.Code,out.Result.Detail)
}

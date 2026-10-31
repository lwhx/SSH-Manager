package main

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "log"
 "os"
 "path/filepath"
 "strings"
 "syscall"
)

const maxOperationReportBytes=8192

// operationReport is immutable once persisted. This is only a delivery
// receipt; it never re-executes a sensitive signed command after a crash.
type operationReport struct {
 OperationID string `json:"operation_id"`
 Status string `json:"status"`
 ResultCode string `json:"result_code"`
 Detail json.RawMessage `json:"detail"`
}
func (a *Agent)operationReportDir()(string,error){
 base:=a.config.StateDir
 if base==""{base=defaultAgentStateDir}
 if !filepath.IsAbs(base)||filepath.Clean(base)!=base||base=="/"{
  return "",errors.New("unsafe Agent operation report state path")
 }
 dir:=filepath.Join(base,"reports")
 if err:=os.MkdirAll(dir,0700);err!=nil{return "",err}
 stat,err:=os.Lstat(dir)
 if err!=nil||!stat.IsDir()||stat.Mode().Perm()&0077!=0{
  return "",errors.New("unsafe operation report directory")
 }
 owner,ok:=stat.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=uint32(os.Geteuid()){
  return "",errors.New("operation reports not owned by Agent service UID")
 }
 return dir,nil
}
func readOperationReport(path string)(operationReport,[]byte,error){
 var report operationReport
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return report,nil,err}
 f:=os.NewFile(uintptr(fd),path);defer f.Close()
 stat,err:=f.Stat()
 if err!=nil||!stat.Mode().IsRegular()||stat.Mode().Perm()&0077!=0||
  stat.Size()>maxOperationReportBytes{
  return report,nil,errors.New("unsafe operation report file")
 }
 owner,ok:=stat.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=uint32(os.Geteuid()){
  return report,nil,errors.New("operation report belongs to different UID")
 }
 raw,err:=io.ReadAll(io.LimitReader(f,maxOperationReportBytes+1))
 if err!=nil||len(raw)>maxOperationReportBytes{
  return report,nil,errors.New("operation report size limit exceeded")
 }
 if err=json.Unmarshal(raw,&report);err!=nil{return report,nil,err}
 if !operationID.MatchString(report.OperationID)||
  (report.Status!="SUCCEEDED"&&report.Status!="FAILED")||
  report.ResultCode==""||len(report.ResultCode)>64{
  return report,nil,errors.New("invalid persisted operation report")
 }
 return report,raw,nil
}
func (a *Agent)enqueueOperationReport(id,status,code string,detail any)error{
 if !operationID.MatchString(id)||(status!="SUCCEEDED"&&status!="FAILED")||
  code==""||len(code)>64{
  return errors.New("invalid terminal operation result")
 }
 rawDetail,err:=json.Marshal(detail)
 if err!=nil{return err}
 entry:=operationReport{OperationID:id,Status:status,ResultCode:code,Detail:rawDetail}
 data,err:=json.Marshal(entry);if err!=nil{return err}
 if len(data)>maxOperationReportBytes{return errors.New("operation result too large")}
 dir,err:=a.operationReportDir();if err!=nil{return err}
 path:=filepath.Join(dir,id+".json")
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_EXCL|os.O_CREATE,0600)
 if errors.Is(err,os.ErrExist){
  old,existing,readErr:=readOperationReport(path)
  if readErr==nil&&old.OperationID==id&&bytes.Equal(existing,data){return nil}
  return errors.New("conflicting or unsafe existing operation report")
 }
 if err!=nil{return err}
 if _,err=f.Write(data);err!=nil{_ = f.Close();return err}
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 if err=f.Close();err!=nil{return err}
 folder,err:=os.Open(dir);if err!=nil{return err}
 defer folder.Close()
 return folder.Sync()
}
// A definitively rejected old operation report must not block newer reports.
// Keep its original JSON and terminal reason in a private Agent-owned archive.
func (a *Agent)quarantineOperationReport(id,reason string)error{
 if !operationID.MatchString(id){return errors.New("invalid report ID")}
 switch reason{
 case "VERIFICATION_PREPARATION_STALE","INVALID_PREPARATION_REPORT",
  "INVALID_POLICY_REPORT","INSTALL_PROOF_MISSING","CONFLICTING_OPERATION_REPORT":
 default:return errors.New("cannot archive unknown operation report error")
 }
 dir,err:=a.operationReportDir();if err!=nil{return err}
 source:=filepath.Join(dir,id+".json")
 if _,_,err=readOperationReport(source);err!=nil{return err}
 archive:=filepath.Join(dir,"rejected")
 if err=os.Mkdir(archive,0700);err!=nil&&!errors.Is(err,os.ErrExist){return err}
 info,err:=os.Lstat(archive)
 if err!=nil||!info.IsDir()||info.Mode().Perm()&0077!=0{
  return errors.New("unsafe archived Agent report directory")
 }
 owner,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=uint32(os.Geteuid()){return errors.New("archived report owner mismatch")}
 target:=filepath.Join(archive,id+".json")
 if _,err=os.Lstat(target);err==nil{
  return errors.New("previous rejected report already archived")
 }else if !errors.Is(err,os.ErrNotExist){return err}
 if err=os.Rename(source,target);err!=nil{return err}
 metadata,err:=os.OpenFile(filepath.Join(archive,id+".reason"),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 if _,err=metadata.WriteString(reason+"\n");err!=nil{_ = metadata.Close();return err}
 if err=metadata.Sync();err!=nil{_ = metadata.Close();return err}
 if err=metadata.Close();err!=nil{return err}
 for _,path:=range []string{archive,dir}{
  folder,err:=os.Open(path);if err!=nil{return err}
  err=folder.Sync();_ = folder.Close()
  if err!=nil{return err}
 }
 return nil
}

func (a *Agent)drainOperationReports(ctx context.Context){
 dir,err:=a.operationReportDir()
 if err!=nil{log.Printf("operation report outbox unavailable: %v",err);return}
 entries,err:=os.ReadDir(dir)
 if err!=nil{log.Printf("operation report read error: %v",err);return}
 processed:=0
 for _,entry:=range entries{
  if processed>=4||ctx.Err()!=nil{return}
  name:=entry.Name()
  if entry.IsDir()||!strings.HasSuffix(name,".json"){continue}
  id:=strings.TrimSuffix(name,".json")
  if !operationID.MatchString(id){continue}
  path:=filepath.Join(dir,name)
  report,_,readErr:=readOperationReport(path)
  if readErr!=nil||report.OperationID!=id{
   log.Printf("unsafe persisted report %s requires manual review",id)
   return
  }
  _,sendErr:=a.request(ctx,"/agent/v1/report",report)
  if sendErr!=nil{
   if reason,terminal:=permanentOperationReportRejection(sendErr);terminal{
    if err=a.quarantineOperationReport(id,reason);err!=nil{
     log.Printf("cannot safely archive terminally rejected report %s: %v",id,err)
     return
    }
    if err=a.markOperationSettled(id);err!=nil{
     log.Printf("cannot persist settled terminal report marker %s: %v",id,err)
     return
    }
    log.Printf("terminal operation report %s archived for operator review (%s)",id,reason)
    processed++
    continue
   }
   // The already-executed command is NEVER replayed just to resubmit
   // its receipt; a network error or unknown status keeps the report.
   log.Printf("operation report %s pending for retry: %v",id,sendErr)
   return
  }
  // The durable receipt settlement prevents a recovery loop from
  // rediscovering this already accepted Root outcome on every restart.
  // Write the marker BEFORE removing the pending HTTP report.
  if err=a.markOperationSettled(id);err!=nil{
   log.Printf("operation result %s accepted but settlement not durable: %v",id,err)
   return
  }
  if err=os.Remove(path);err!=nil{
   log.Printf("operation report ACK cleanup deferred: %v",err)
   return
  }
  processed++
 }
 if processed>0{
  folder,err:=os.Open(dir)
  if err!=nil{log.Printf("operation report directory sync: %v",err);return}
  if err=folder.Sync();err!=nil{log.Printf("operation report directory sync: %v",err)}
  _=folder.Close()
 }
}
func (r operationReport)String()string{
 return fmt.Sprintf("operation=%s status=%s code=%s",r.OperationID,r.Status,r.ResultCode)
}

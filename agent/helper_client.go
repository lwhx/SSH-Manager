package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "time"
)

type LocalHelperResult struct {
 OK bool `json:"ok"`
 Code string `json:"code"`
 Detail json.RawMessage `json:"detail"`
}
// sendToLocalHelper forwards the EXACT signed command bytes. The root helper
// independently verifies signature, target node, deadline and policy revision.
// A missing helper must fail closed: the Agent NEVER edits SSH files itself.
func (a *Agent) sendToLocalHelper(ctx context.Context,s SignedCommand)(LocalHelperResult,error){
 var result LocalHelperResult
 socket:=a.config.HelperSocket
 if socket!="/run/ssh-manager/helper.sock"{
  return result,errors.New("ROOT_HELPER_NOT_CONFIGURED")
 }
 deadlineCtx,cancel:=context.WithTimeout(ctx,12*time.Second)
 defer cancel()
 conn,err:=(&net.Dialer{}).DialContext(deadlineCtx,"unix",socket)
 if err!=nil{return result,fmt.Errorf("ROOT_HELPER_OFFLINE: %w",err)}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(12*time.Second))
 data,err:=json.Marshal(s)
 if err!=nil{return result,err}
 if len(data)>16384{return result,errors.New("signed helper request too large")}
 if _,err=conn.Write(data);err!=nil{return result,err}
 if uc,ok:=conn.(*net.UnixConn);ok{
  if err=uc.CloseWrite();err!=nil{return result,err}
 }
 reply,err:=io.ReadAll(io.LimitReader(conn,8193))
 if err!=nil||len(reply)>8192{return result,errors.New("invalid helper response size")}
 if err=json.Unmarshal(reply,&result);err!=nil{return result,fmt.Errorf("helper response: %w",err)}
 if result.Code==""{return result,errors.New("helper response missing result code")}
 return result,nil
}

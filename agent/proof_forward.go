package main

import (
 "context"
 "encoding/json"
 "errors"
 "io"
 "log"
 "net"
 "regexp"
 "time"
)

type proofEnvelope struct {
 Payload string `json:"payload"`
 Signature string `json:"signature"`
}
type localProofReply struct {
 OK bool `json:"ok"`
 Code string `json:"code"`
 Proof proofEnvelope `json:"proof"`
}
var proofIDRE=regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
func (a *Agent)localProofCall(ctx context.Context,request map[string]string)(localProofReply,error){
 var reply localProofReply
 if a.config.HelperSocket!="/run/ssh-manager/helper.sock"{
  return reply,errors.New("local helper not configured")
 }
 scope,cancel:=context.WithTimeout(ctx,6*time.Second);defer cancel()
 conn,err:=(&net.Dialer{}).DialContext(scope,"unix",a.config.HelperSocket)
 if err!=nil{return reply,err}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(6*time.Second))
 data,_:=json.Marshal(request)
 if _,err=conn.Write(data);err!=nil{return reply,err}
 if c,ok:=conn.(*net.UnixConn);ok{_ = c.CloseWrite()}
 b,err:=io.ReadAll(io.LimitReader(conn,12289))
 if err!=nil||len(b)>12288{return reply,errors.New("local proof response oversized")}
 if err=json.Unmarshal(b,&reply);err!=nil{return reply,err}
 return reply,nil
}
// Forward a root-signed proof; the Agent may relay but cannot forge the
// signing key or produce a VERIFIED result without Cloudflare D1 checks.
func (a *Agent)drainProofOutbox(ctx context.Context){
 // Drain a bounded number of entries each heartbeat, so a permanently
 // rejected old challenge cannot block a newer one. Never discard on a
 // timeout, Cloudflare outage, device authentication failure, or 5xx.
 for tries:=0;tries<4&&ctx.Err()==nil;tries++{
  reply,err:=a.localProofCall(ctx,map[string]string{"local_action":"proof.peek"})
  if err!=nil||!reply.OK||reply.Proof.Payload==""{return}
  if len(reply.Proof.Payload)>4096||len(reply.Proof.Signature)>128{
   log.Print("oversized root SSH proof requires manual review");return
  }
  var body struct{
   ProofID string `json:"proof_id"`
  }
  if json.Unmarshal([]byte(reply.Proof.Payload),&body)!=nil||!proofIDRE.MatchString(body.ProofID){
   log.Print("invalid root SSH proof outbox entry requires manual review");return
  }
  _,err=a.request(ctx,"/agent/v1/ssh-proof",map[string]string{
   "payload":reply.Proof.Payload,"signature":reply.Proof.Signature,
  })
  if err!=nil{
   if reason,permanent:=permanentProofRejection(err);permanent{
    saved,storeErr:=a.localProofCall(ctx,map[string]string{
     "local_action":"proof.quarantine","proof_id":body.ProofID,"reason":reason,
    })
    if storeErr!=nil||!saved.OK||saved.Code!="PROOF_QUARANTINED"{
     log.Printf("cannot safely quarantine terminal proof response: %v",storeErr)
     return
    }
    log.Printf("terminally rejected SSH proof %s quarantined root-only (%s)",body.ProofID,reason)
    continue
   }
   log.Printf("root proof pending: retryable or unknown cloud response: %v",err)
   return
  }
  ack,ackErr:=a.localProofCall(ctx,map[string]string{
   "local_action":"proof.ack","proof_id":body.ProofID,
  })
  if ackErr!=nil||!ack.OK||ack.Code!="ACK_RECORDED"{
   log.Printf("root proof acknowledgement deferred: %v",ackErr)
   return
  }
 }
}

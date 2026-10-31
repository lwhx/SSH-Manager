package main

import (
 "encoding/json"
 "net"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

const challengeID="10000000-0000-4000-8000-000000000001"
const nonce43="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"

func localProofServer(t *testing.T,handler func(*net.UnixConn))string{
 t.Helper()
 path:=filepath.Join(t.TempDir(),"proof.sock")
 listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:path,Net:"unix"})
 if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = listener.Close()})
 done:=make(chan struct{})
 go func(){
  defer close(done)
  connection,acceptErr:=listener.AcceptUnix()
  if acceptErr==nil{handler(connection);_ = connection.Close()}
 }()
 t.Cleanup(func(){select{case <-done:case <-time.After(3*time.Second):t.Error("proof socket handler stuck")}})
 return path
}
func TestNewSSHSessionProofSendsNonceOnlyToLocalSocket(t *testing.T){
 received:=make(chan map[string]string,1)
 path:=localProofServer(t,func(c *net.UnixConn){
  _=c.SetDeadline(time.Now().Add(3*time.Second))
  var req map[string]string
  if err:=json.NewDecoder(c).Decode(&req);err!=nil{received<-map[string]string{"error":err.Error()};return}
  received<-req
  _=json.NewEncoder(c).Encode(map[string]any{"ok":true,"code":"SIGNED_PROOF_QUEUED"})
 })
 if err:=runAtSocket(path,challengeID,nonce43);err!=nil{t.Fatal(err)}
 req:=<-received
 if len(req)!=2||req["verification_id"]!=challengeID||req["nonce"]!=nonce43{
  t.Fatalf("wrong proof socket request: %+v",req)
 }
}
func TestProveRejectsFakeOrUntrustedResponses(t *testing.T){
 for _,reply:=range []string{
  `{"ok":true,"code":"VERIFIED"}`,
  `{"ok":false,"code":"SIGNED_PROOF_QUEUED"}`,
  `{"ok":true,"code":"ROOT_HELPER_DISABLED"}`,
 }{
  t.Run(reply,func(t *testing.T){
   path:=localProofServer(t,func(c *net.UnixConn){
    _,_ = c.Write([]byte(reply))
   })
   if err:=runAtSocket(path,challengeID,nonce43);err==nil{
    t.Fatal("accepted unsupported proof helper response")
   }
  })
 }
}
func TestProveRefusesMalformedChallengeBeforeDial(t *testing.T){
 for _,value:=range []string{"","not-a-uuid",strings.Repeat("a",128)}{
  if err:=runAtSocket("/socket/must/not/exist",value,nonce43);err==nil{
   t.Fatal("accepted malformed verification id")
  }
 }
 if err:=runAtSocket("/socket/must/not/exist",challengeID,"short");err==nil{
  t.Fatal("accepted malformed challenge token")
 }
}

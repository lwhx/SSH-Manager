package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "errors"
 "net"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "sync/atomic"
 "testing"
 "time"

 "github.com/lwhx/SSH-Manager/agent/internal/sshhelper"
)

// A local Unix socket stands in for the root-only helper transport; the
// returned recovery record comes from a real disk-fsynced Root Journal.
func serveOneRootJournalRecovery(t *testing.T,j *sshhelper.Journal,node string)(string,func()){
 t.Helper()
 socket:=filepath.Join(t.TempDir(),"root.sock")
 listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:socket,Net:"unix"})
 if err!=nil{t.Fatal(err)}
 done:=make(chan struct{})
 go func(){
  defer close(done)
  conn,err:=listener.AcceptUnix()
  if err!=nil{return}
  defer conn.Close()
  _=conn.SetDeadline(time.Now().Add(5*time.Second))
  var request struct {
   LocalAction string `json:"local_action"`
   OperationID string `json:"operation_id"`
   Action string `json:"action"`
  }
  if json.NewDecoder(conn).Decode(&request)!=nil||
   request.LocalAction!="operation.recover"{return}
  recovered,err:=j.Recover(request.OperationID,node,request.Action)
  if err!=nil{return}
  _=json.NewEncoder(conn).Encode(recovered)
 }()
 cleanup:=func(){
  _=listener.Close()
  select{case <-done:case <-time.After(5*time.Second):t.Error("Root recovery test socket stalled")}
 }
 return socket,cleanup
}
func newRecoveryAgent(t *testing.T,gateway string,httpClient *http.Client)*Agent{
 t.Helper()
 _,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 return &Agent{config:Config{
  NodeID:"10000000-0000-4000-8000-000000000001",
  Gateway:gateway,StateDir:t.TempDir(),HelperSocket:helperJournalSocket,
 },secret:private,http:httpClient}
}
func TestRecoveryAfterRootFinishesBeforeAgentSavesResult(t *testing.T){
 var delivered atomic.Int32
 httpServer:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!="/agent/v1/report"{http.Error(w,"route",404);return}
  var report operationReport
  if json.NewDecoder(r.Body).Decode(&report)!=nil||
   report.Status!="SUCCEEDED"||report.ResultCode!="DAILY_KEY_WRITTEN_AWAITING_LOGIN_PROOF"{
   http.Error(w,"wrong recovered Root report",400);return
  }
  delivered.Add(1)
  w.Header().Set("Content-Type","application/json")
  _,_=w.Write([]byte(`{"accepted":true}`))
 }))
 defer httpServer.Close()
 a:=newRecoveryAgent(t,httpServer.URL,httpServer.Client())
 cmd:=Command{
  ID:"20000000-0000-4000-8000-000000000001",
  NodeID:a.config.NodeID,Action:"ssh.daily.install",IssuedAt:time.Now().Unix()-2,
 }
 if err:=a.claimOperation(cmd);err!=nil{t.Fatal(err)}
 root:=&sshhelper.Journal{Directory:filepath.Join(t.TempDir(),"root-journal")}
 if err:=root.Claim(cmd.ID,cmd.NodeID,cmd.Action);err!=nil{t.Fatal(err)}
 // Simulate Helper completing authorized_keys install, then Agent crashing
 // before saving any terminal result locally.
 if err:=root.Finalize(cmd.ID,cmd.NodeID,cmd.Action,sshhelper.Result{
  OK:true,Code:"DAILY_KEY_WRITTEN_AWAITING_LOGIN_PROOF",
  Detail:map[string]any{"key_fingerprint":"SHA256:test","file_checked":true},
 });err!=nil{t.Fatal(err)}
 if _,err:=os.Stat(filepath.Join(a.config.StateDir,"reports",cmd.ID+".json"));!errors.Is(err,os.ErrNotExist){
  t.Fatal("test did not simulate missing Agent response")
 }
 socket,stop:=serveOneRootJournalRecovery(t,root,cmd.NodeID)
 a.recoverClaimedOperationsWithSocket(context.Background(),socket)
 stop()
 reportPath:=filepath.Join(a.config.StateDir,"reports",cmd.ID+".json")
 saved,_,err:=readOperationReport(reportPath)
 if err!=nil||saved.Status!="SUCCEEDED"{
  t.Fatalf("Agent did not persist Root-confirmed result: %+v %v",saved,err)
 }
 // Simulate another Agent process start, then cloud ACK, without a second
 // Root Helper Execute call.
 reloaded:=&Agent{config:a.config,http:httpServer.Client(),secret:a.secret}
 reloaded.drainOperationReports(context.Background())
 if delivered.Load()!=1{t.Fatal("recovered report not delivered exactly once")}
 if _,err=os.Stat(reportPath);!errors.Is(err,os.ErrNotExist){
  t.Fatal("acknowledged recovered report not removed")
 }
 settled:=filepath.Join(a.config.StateDir,"operations",cmd.ID+".settled")
 if _,err=os.Stat(settled);err!=nil{t.Fatal("receipt settlement not persisted",err)}
 // No remaining Root socket exists; a settled operation must never try to
 // replay the original signed SSH command or even request a new result.
 reloaded.recoverClaimedOperationsWithSocket(context.Background(),"/nonexistent/ssh-helper.sock")
 if delivered.Load()!=1{t.Fatal("settled Root action re-reported after restart")}
}
func TestUnconfirmedRootWriteNeverBecomesSucceededOrFailed(t *testing.T){
 a:=newRecoveryAgent(t,"https://unused.example",&http.Client{})
 cmd:=Command{
  ID:"30000000-0000-4000-8000-000000000001",
  NodeID:a.config.NodeID,Action:"ssh.daily.install",
  IssuedAt:time.Now().Unix()-125,
 }
 if err:=a.claimOperation(cmd);err!=nil{t.Fatal(err)}
 root:=&sshhelper.Journal{Directory:filepath.Join(t.TempDir(),"root-journal")}
 if err:=root.Claim(cmd.ID,cmd.NodeID,cmd.Action);err!=nil{t.Fatal(err)}
 socket,stop:=serveOneRootJournalRecovery(t,root,cmd.NodeID)
 a.recoverClaimedOperationsWithSocket(context.Background(),socket)
 stop()
 review:=filepath.Join(a.config.StateDir,"operations",cmd.ID+".review")
 content,err:=os.ReadFile(review)
 if err!=nil||string(content)!="UNCONFIRMED\n"{
  t.Fatalf("incomplete root journal was not flagged for manual review: %q %v",content,err)
 }
 if _,err=os.Stat(filepath.Join(a.config.StateDir,"reports",cmd.ID+".json"));!errors.Is(err,os.ErrNotExist){
  t.Fatal("unconfirmed authorized_keys action produced a fake operation report")
 }
}
func TestRecoveryRejectsDifferentNodeAndUntrustedReceipt(t *testing.T){
 a:=newRecoveryAgent(t,"https://unused.example",&http.Client{})
 other:=Command{
  ID:"40000000-0000-4000-8000-000000000001",
  NodeID:"50000000-0000-4000-8000-000000000001",
  Action:"ssh.policy.inspect",IssuedAt:time.Now().Unix()-3,
 }
 if err:=a.claimOperation(other);err!=nil{t.Fatal(err)}
 root:=&sshhelper.Journal{Directory:filepath.Join(t.TempDir(),"journal")}
 if err:=root.Claim(other.ID,other.NodeID,other.Action);err!=nil{t.Fatal(err)}
 if err:=root.Finalize(other.ID,other.NodeID,other.Action,
  sshhelper.Result{OK:true,Code:"POLICY_INSPECTED"});err!=nil{t.Fatal(err)}
 // Agent must skip an operation receipt that belongs to a different VPS.
 a.recoverClaimedOperationsWithSocket(context.Background(),"/nonexistent/socket")
 if _,err:=os.Stat(filepath.Join(a.config.StateDir,"reports",other.ID+".json"));!errors.Is(err,os.ErrNotExist){
  t.Fatal("cross-node Root result was recovered")
 }
 dir:=filepath.Join(a.config.StateDir,"operations")
 evilID:="60000000-0000-4000-8000-000000000001"
 link:=filepath.Join(dir,evilID+".json")
 if err:=os.Symlink(filepath.Join(dir,other.ID+".json"),link);err!=nil{t.Fatal(err)}
 if _,err:=readClaimedOperation(link);err==nil{t.Fatal("accepted symlinked Agent receipt")}
}

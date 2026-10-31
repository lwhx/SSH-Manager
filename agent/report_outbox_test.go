package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "errors"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "sync/atomic"
 "testing"
)

func newReportTestAgent(t *testing.T, gateway string, httpClient *http.Client)*Agent{
 t.Helper()
 _,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 return &Agent{
  config:Config{Gateway:gateway,NodeID:"10000000-0000-4000-8000-000000000001",StateDir:t.TempDir()},
  secret:private,http:httpClient,
 }
}
func TestAgentPersistsTerminalResultAcrossDisconnectAndRestart(t *testing.T){
 var tries atomic.Int32
 received:=make(chan operationReport,3)
 server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!="/agent/v1/report"{http.Error(w,"wrong route",404);return}
  var payload operationReport
  if err:=json.NewDecoder(r.Body).Decode(&payload);err!=nil{
   http.Error(w,"invalid report",400);return
  }
  received<-payload
  if tries.Add(1)==1{
   w.Header().Set("Content-Type","application/json")
   w.WriteHeader(http.StatusServiceUnavailable)
   _,_ = w.Write([]byte(`{"error":"INTERNAL_ERROR"}`))
   return
  }
  w.Header().Set("Content-Type","application/json")
  _,_ = w.Write([]byte(`{"accepted":true}`))
 }))
 defer server.Close()
 agent:=newReportTestAgent(t,server.URL,server.Client())
 id:="20000000-0000-4000-8000-000000000001"
 detail:=map[string]any{"verification_id":"30000000-0000-4000-8000-000000000001","verified_login":false}
 if err:=agent.enqueueOperationReport(id,"SUCCEEDED","VERIFICATION_PREPARED",detail);err!=nil{t.Fatal(err)}
 path:=filepath.Join(agent.config.StateDir,"reports",id+".json")
 if err:=agent.enqueueOperationReport(id,"SUCCEEDED","VERIFICATION_PREPARED",detail);err!=nil{
  t.Fatal("repeated identical result must not overwrite durable report",err)
 }
 if err:=agent.enqueueOperationReport(id,"FAILED","DIFFERENT_RESULT",detail);err==nil{
  t.Fatal("conflicting result unexpectedly replaced saved report")
 }
 agent.drainOperationReports(context.Background())
 if _,err:=os.Stat(path);err!=nil{t.Fatal("503 incorrectly deleted persisted report",err)}
 // Simulate Agent process restart with the same on-disk identity and key.
 restarted:=&Agent{config:agent.config,secret:agent.secret,http:server.Client()}
 restarted.drainOperationReports(context.Background())
 if _,err:=os.Stat(path);!errors.Is(err,os.ErrNotExist){
  t.Fatalf("confirmed report should be acknowledged and removed: %v",err)
 }
 if tries.Load()!=2{t.Fatalf("expected automatic retry after restart, got %d sends",tries.Load())}
 for range 2 {
  actual:=<-received
  if actual.OperationID!=id||actual.Status!="SUCCEEDED"||actual.ResultCode!="VERIFICATION_PREPARED"{
   t.Fatalf("retries changed original signed operation result: %+v",actual)
  }
 }
}
func TestReportOutboxRejectsSymlinksAndUnsafePermissions(t *testing.T){
 agent:=newReportTestAgent(t,"https://example.test",&http.Client{})
 id:="20000000-0000-4000-8000-000000000001"
 if err:=agent.enqueueOperationReport(id,"SUCCEEDED","OK",nil);err!=nil{t.Fatal(err)}
 path:=filepath.Join(agent.config.StateDir,"reports",id+".json")
 if err:=os.Chmod(path,0644);err!=nil{t.Fatal(err)}
 if err:=agent.enqueueOperationReport(id,"SUCCEEDED","OK",nil);err==nil{
  t.Fatal("unsafe persisted report accepted by idempotent report check")
 }
 linkID:="20000000-0000-4000-8000-000000000002"
 link:=filepath.Join(agent.config.StateDir,"reports",linkID+".json")
 if err:=os.Symlink(path,link);err!=nil{t.Fatal(err)}
 if err:=agent.enqueueOperationReport(linkID,"SUCCEEDED","OK",nil);err==nil{
  t.Fatal("symlinked persisted report accepted")
 }
}

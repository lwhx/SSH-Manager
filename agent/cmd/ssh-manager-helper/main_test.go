package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "net"
 "os"
 "path/filepath"
 "strings"
 "syscall"
 "testing"
 "time"

 "github.com/lwhx/SSH-Manager/agent/internal/sshhelper"
 "github.com/lwhx/SSH-Manager/agent/internal/sshprobe"
)
func testListener(t *testing.T)(*net.UnixListener,*sshhelper.Handler,ed25519.PrivateKey){
 t.Helper()
 addr:=filepath.Join(t.TempDir(),"h.sock")
 listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:addr,Net:"unix"})
 if err!=nil{t.Fatal(err)}
 pub,key,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{listener.Close();t.Fatal(err)}
 h:=&sshhelper.Handler{
  Config:sshhelper.Config{NodeID:"10000000-0000-4000-8000-000000000001",CommandPublicKey:base64.RawURLEncoding.EncodeToString(pub),
   AllowedUser:"root",ClientAddress:"192.0.2.10",LocalAddress:"192.0.2.11",SSHPort:22,SnapshotRoot:t.TempDir()},
  Journal:&sshhelper.Journal{Directory:filepath.Join(t.TempDir(),"journal")},
  EUID:func()int{return 0},
  Clock:func()time.Time{return time.Unix(1000,0)},
  Inspect:func(context.Context,sshhelper.Config)(sshprobe.Effective,error){
   return sshprobe.Effective{PublicKeyAuthentication:true,AuthenticationMethods:"any",AuthorizedKeysFile:[]string{".ssh/authorized_keys"},
    PermitRootLogin:"prohibit-password",Revision:"policy123"},nil
  },
 }
 return listener,h,key
}
func testRequest(t *testing.T,key ed25519.PrivateKey)[]byte{
 t.Helper()
 cmd:=sshhelper.Command{V:1,ID:"20000000-0000-4000-8000-000000000001",NodeID:"10000000-0000-4000-8000-000000000001",Action:"ssh.policy.inspect",
  Actor:"owner",IssuedAt:990,ExpiresAt:1030,ExpectedRevision:"unverified",Payload:json.RawMessage("{}")}
 raw,_:=json.Marshal(cmd)
 signed:=sshhelper.SignedCommand{Command:string(raw),Signature:base64.RawURLEncoding.EncodeToString(ed25519.Sign(key,raw))}
 data,_:=json.Marshal(signed)
 return data
}
func TestPeerCredentialsAcceptSignedInspect(t *testing.T){
 listener,h,key:=testListener(t)
 defer listener.Close()
 done:=make(chan struct{})
 go func(){conn,err:=listener.AcceptUnix();if err==nil{handle(conn,uint32(os.Getuid()),h)};close(done)}()
 conn,err:=net.DialUnix("unix",nil,listener.Addr().(*net.UnixAddr))
 if err!=nil{t.Fatal(err)}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(3*time.Second))
 if _,err=conn.Write(testRequest(t,key));err!=nil{t.Fatal(err)}
 if err=conn.CloseWrite();err!=nil{t.Fatal(err)}
 var response sshhelper.Result
 if err=json.NewDecoder(conn).Decode(&response);err!=nil{t.Fatal(err)}
 if !response.OK||response.Code!="POLICY_INSPECTED"{t.Fatalf("unexpected response %+v",response)}
 <-done
}
func TestPeerCredentialsDenyOtherUID(t *testing.T){
 listener,h,key:=testListener(t)
 defer listener.Close()
 done:=make(chan struct{})
 go func(){conn,err:=listener.AcceptUnix();if err==nil{handle(conn,uint32(os.Getuid()+1),h)};close(done)}()
 conn,err:=net.DialUnix("unix",nil,listener.Addr().(*net.UnixAddr))
 if err!=nil{t.Fatal(err)}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(3*time.Second))
 _,_ = conn.Write(testRequest(t,key))
 _ = conn.CloseWrite()
 var response sshhelper.Result
 if err=json.NewDecoder(conn).Decode(&response);err==nil{t.Fatal("unauthorized socket peer received response")}
 <-done
}


func TestProofSocketUsesKernelPeerCredentialsAndFailClosed(t *testing.T){
 listener,h,_:=testListener(t)
 defer listener.Close()
 observed:=make(chan *syscall.Ucred,1)
 completed:=make(chan struct{})
 go func(){
  conn,err:=listener.AcceptUnix()
  if err==nil{
   creds,credErr:=peerCredentials(conn)
   if credErr!=nil{observed<-nil}else{observed<-creds}
   handleProof(conn,h)
  }else{observed<-nil}
  close(completed)
 }()
 client,err:=net.DialUnix("unix",nil,listener.Addr().(*net.UnixAddr))
 if err!=nil{t.Fatal(err)}
 defer client.Close()
 _=client.SetDeadline(time.Now().Add(3*time.Second))
 request,_:=json.Marshal(sshhelper.ProofRequest{
  VerificationID:"40000000-0000-4000-8000-000000000001",
  Nonce:strings.Repeat("A",43),
 })
 if _,err=client.Write(request);err!=nil{t.Fatal(err)}
 if err=client.CloseWrite();err!=nil{t.Fatal(err)}
 var result sshhelper.ProofResult
 if err=json.NewDecoder(client).Decode(&result);err!=nil{t.Fatal(err)}
 if result.OK||result.Code!="PROOF_FEATURE_DISABLED"{
  t.Fatalf("disabled proof socket must fail closed: %+v",result)
 }
 creds:=<-observed
 if creds==nil||int(creds.Pid)!=os.Getpid()||int(creds.Uid)!=os.Getuid(){
  t.Fatalf("kernel proof credentials missing or incorrect: %+v",creds)
 }
 <-completed
}

//go:build linux

package sshproof

import (
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "testing"
 "time"
)
func TestAuthenticatedKernelPeerAndChallengeBoundToSSHD(t *testing.T){
 secret:=make([]byte,32)
 for i:=range secret{secret[i]=byte(i)}
 nonce:=base64.RawURLEncoding.EncodeToString(secret)
 hash:=sha256.Sum256([]byte(nonce))
 proofHash:=hex.EncodeToString(hash[:])
 issued:=time.Unix(1793440000,0)
 event:=Event{PID:100,SourcePath:"/usr/sbin/sshd",User:"root",
  ClientIP:"203.0.113.9",ClientPort:52133,Fingerprint:fingerprint,
  Timestamp:issued.Add(10*time.Second)}
 challenge:=Challenge{LoginUser:"root",KeyFingerprint:fingerprint,
  ClientIP:"203.0.113.9",ClientPort:52133,IssuedAt:issued,
  ExpiresAt:issued.Add(5*time.Minute)}
 peer:=TrustedPeer{PID:300,RealUID:0}
 procs:=map[int]ProcState{
  300:{PID:300,PPID:200,RealUID:0,Executable:"/usr/local/bin/prove"},
  200:{PID:200,PPID:100,RealUID:0,Executable:"/bin/sh"},
  100:{PID:100,PPID:1,RealUID:0,Executable:"/usr/sbin/sshd"},
 }
 lookup:=func(pid int)(ProcState,error){return procs[pid],nil}
 if err:=VerifyLocalSSHProof(peer,0,nonce,proofHash,challenge,event,lookup);err!=nil{t.Fatal(err)}
 if err:=VerifyLocalSSHProof(peer,0,nonce+"X",proofHash,challenge,event,lookup);err==nil{
  t.Fatal("modified challenge accepted")
 }
 if err:=VerifyLocalSSHProof(TrustedPeer{PID:300,RealUID:1000},0,nonce,proofHash,challenge,event,lookup);err==nil{
  t.Fatal("wrong Unix peer UID accepted")
 }
 wrong:=event;wrong.PID=101
 if err:=VerifyLocalSSHProof(peer,0,nonce,proofHash,challenge,wrong,lookup);err==nil{
  t.Fatal("accepted sshd log from another login")
 }
 old:=event;old.Timestamp=issued.Add(-time.Second)
 if err:=VerifyLocalSSHProof(peer,0,nonce,proofHash,challenge,old,lookup);err==nil{
  t.Fatal("accepted SSH login that predates challenge")
 }
}

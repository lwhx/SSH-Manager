//go:build linux

package sshproof

import (
 "bytes"
 "encoding/json"
 "fmt"
 "strings"
 "testing"
 "time"
)
func testJournalAuth(t *testing.T,msg string,uid string,pid string,at time.Time)[]byte{
 t.Helper()
 data,err:=json.Marshal(map[string]string{
  "MESSAGE":msg,"_EXE":"/usr/sbin/sshd","_UID":uid,
  "_PID":pid,"__REALTIME_TIMESTAMP":fmt.Sprint(at.UnixMicro()),
 })
 if err!=nil{t.Fatal(err)}
 return data
}
func TestOnlyExactKernelSSHAncestryMaySatisfyVerification(t *testing.T){
 at:=time.Unix(1793440000,0)
 expected:=Challenge{LoginUser:"root",KeyFingerprint:fingerprint,
  IssuedAt:at,ExpiresAt:at.Add(5*time.Minute)}
 processes:=map[int]ProcState{
  300:{PID:300,PPID:200,RealUID:1000,Executable:"/usr/bin/ssh-manager-prove"},
  200:{PID:200,PPID:100,RealUID:1000,Executable:"/bin/sh"},
  100:{PID:100,PPID:1,RealUID:0,Executable:"/usr/sbin/sshd"},
  101:{PID:101,PPID:1,RealUID:0,Executable:"/usr/sbin/sshd"},
 }
 read:=func(pid int)(ProcState,error){return processes[pid],nil}
 bad:=testJournalAuth(t,acceptedMessage,"0","101",at.Add(time.Second))
 good:=testJournalAuth(t,acceptedMessage,"0","100",at.Add(2*time.Second))
 forged:=testJournalAuth(t,acceptedMessage,"1000","100",at.Add(3*time.Second))
 output:=bytes.Join([][]byte{bad,good,forged},[]byte("\n"))
 event,err:=FindSessionEvent(output,300,expected,read)
 if err!=nil||event.PID!=100{t.Fatalf("did not bind to exact sshd process: %+v %v",event,err)}
 if _,err:=FindSessionEvent(bytes.Join([][]byte{good,good},[]byte("\n")),300,expected,read);err==nil{
  t.Fatal("accepted duplicate authentication event")
 }
 if _,err:=FindSessionEvent(bad,300,expected,read);err==nil{t.Fatal("accepted unrelated sshd PID")}
}
func TestRejectPasswordAuthAndPreChallengeSessions(t *testing.T){
 at:=time.Unix(1793440000,0)
 expected:=Challenge{LoginUser:"root",KeyFingerprint:fingerprint,IssuedAt:at,ExpiresAt:at.Add(5*time.Minute)}
 reader:=func(pid int)(ProcState,error){
  if pid==300{return ProcState{PID:300,PPID:100,RealUID:0,Executable:"/usr/bin/ssh-manager-prove"},nil}
  return ProcState{PID:100,PPID:1,RealUID:0,Executable:"/usr/sbin/sshd"},nil
 }
 wrongPassword:=testJournalAuth(t,strings.Replace(acceptedMessage,"publickey","password",1),"0","100",at.Add(time.Second))
 older:=testJournalAuth(t,acceptedMessage,"0","100",at.Add(-time.Second))
 for _,sample:=range [][]byte{wrongPassword,older}{
  if _,err:=FindSessionEvent(sample,300,expected,reader);err==nil{t.Fatal("accepted invalid SSH login evidence")}
 }
}

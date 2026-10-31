package sshproof

import (
 "bytes"
 "encoding/json"
 "fmt"
 "strings"
 "testing"
 "time"
)
func journalEvent(t *testing.T,log string,exe string,stamp time.Time)[]byte{
 t.Helper()
 r:=map[string]string{
  "MESSAGE":log,"_EXE":exe,"_UID":"0","_PID":"2145",
  "__REALTIME_TIMESTAMP":fmt.Sprint(stamp.UnixMicro()),
 }
 b,err:=json.Marshal(r)
 if err!=nil{t.Fatal(err)}
 return b
}
func TestSelectsOnlyTrustedEventForTheExactSSHConnection(t *testing.T){
 begin:=time.Unix(1793440000,0)
 want:=Challenge{LoginUser:"root",KeyFingerprint:fingerprint,ClientIP:"203.0.113.9",ClientPort:52133,
  IssuedAt:begin,ExpiresAt:begin.Add(5*time.Minute)}
 data:=bytes.Join([][]byte{
  journalEvent(t,acceptedMessage,"/usr/bin/logger",begin.Add(time.Second)),
  journalEvent(t,strings.Replace(acceptedMessage,"52133","52134",1),"/usr/sbin/sshd",begin.Add(time.Second*2)),
  journalEvent(t,acceptedMessage,"/usr/sbin/sshd",begin.Add(time.Second*5)),
 },[]byte("\n"))
 result,err:=MatchOneFromJournal(data,want)
 if err!=nil{t.Fatal(err)}
 if result.ClientPort!=52133||result.PID!=2145{t.Fatal("incorrect SSH connection selected")}
}
func TestRejectsAmbiguousOldAndMaliciousJournal(t *testing.T){
 start:=time.Unix(1793440000,0)
 want:=Challenge{LoginUser:"root",KeyFingerprint:fingerprint,ClientIP:"203.0.113.9",ClientPort:52133,
  IssuedAt:start,ExpiresAt:start.Add(5*time.Minute)}
 valid:=journalEvent(t,acceptedMessage,"/usr/sbin/sshd",start.Add(time.Second))
 old:=journalEvent(t,acceptedMessage,"/usr/sbin/sshd",start.Add(-time.Second))
 forged:=journalEvent(t,acceptedMessage,"/usr/bin/logger",start.Add(time.Second))
 for name,lines:=range map[string][]byte{
  "old only":old,
  "forged only":forged,
  "duplicate valid":bytes.Join([][]byte{valid,valid},[]byte("\n")),
  "oversized":bytes.Repeat([]byte("x"),maxJournalEvidenceBytes+1),
 }{
  t.Run(name,func(t *testing.T){
   if _,err:=MatchOneFromJournal(lines,want);err==nil{t.Fatal("accepted untrustworthy SSH evidence")}
  })
 }
}

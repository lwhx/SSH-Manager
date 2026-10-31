//go:build linux

package sshproof

import (
 "bufio"
 "bytes"
 "context"
 "errors"
 "io"
 "os"
 "os/exec"
 "strconv"
 "time"
)

// FindSessionEvent finds EXACTLY one root-owned sshd Accepted publickey event
// whose recorded PID is an ancestor of the local SSH verifier's kernel PID.
// It never trusts SSH_CONNECTION, a client TCP port, or a fabricated log.
func FindSessionEvent(journal []byte,peerPID int,expect Challenge,
 reader ProcessReader)(Event,error){
 var matched Event
 if len(journal)==0||len(journal)>maxJournalEvidenceBytes{
  return matched,errors.New("SSH journal evidence unavailable or too large")
 }
 s:=bufio.NewScanner(bytes.NewReader(journal))
 s.Buffer(make([]byte,1024),32768)
 total:=0
 for s.Scan(){
  ev,err:=ParseTrustedJournal(bytes.TrimSpace(s.Bytes()))
  if err!=nil{continue}
  if ev.User!=expect.LoginUser||ev.Fingerprint!=expect.KeyFingerprint{continue}
  // The trusted event already has its real TCP tuple; never populate that
  // tuple from client-provided process environment.
  check:=expect;check.ClientIP=ev.ClientIP;check.ClientPort=ev.ClientPort
  if Match(ev,check)!=nil{continue}
  if MatchSSHDAncestor(peerPID,ev,reader)!=nil{continue}
  total++
  if total>1{return Event{},errors.New("ambiguous SSH session authentication evidence")}
  matched=ev
 }
 if err:=s.Err();err!=nil{return Event{},err}
 if total!=1{return Event{},errors.New("no trusted authentication event for this SSH session")}
 return matched,nil
}

// ObserveLinuxSSHLogin reads only the *host's own* journald using a fixed
// absolute executable and bounded stdout. This function must run as root.
func ObserveLinuxSSHLogin(ctx context.Context,peerPID int,
 expect Challenge,reader ProcessReader)(Event,error){
 if os.Geteuid()!=0{return Event{},errors.New("SSH login evidence requires root")}
 if peerPID<=1||reader==nil{return Event{},errors.New("untrusted local SSH peer")}
 if expect.IssuedAt.IsZero()||expect.ExpiresAt.IsZero()||
  !expect.ExpiresAt.After(expect.IssuedAt)||expect.ExpiresAt.Sub(expect.IssuedAt)>5*time.Minute{
  return Event{},errors.New("invalid SSH challenge window")
 }
 now:=time.Now()
 if now.Before(expect.IssuedAt)||!now.Before(expect.ExpiresAt){
  return Event{},errors.New("SSH challenge is not active")
 }
 scope,cancel:=context.WithTimeout(ctx,6*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(scope,"/usr/bin/journalctl",
  "--quiet","--no-pager","--output=json",
  "--since=@"+strconv.FormatInt(expect.IssuedAt.Unix(),10),
  "--until=@"+strconv.FormatInt(now.Unix()+1,10),
  "--identifier=sshd","--identifier=sshd-session")
 cmd.Stderr=io.Discard
 stdout,err:=cmd.StdoutPipe()
 if err!=nil{return Event{},errors.New("cannot query SSH authentication journal")}
 if err=cmd.Start();err!=nil{return Event{},errors.New("local SSH journald unavailable")}
 data,err:=io.ReadAll(io.LimitReader(stdout,maxJournalEvidenceBytes+1))
 if err!=nil||len(data)>maxJournalEvidenceBytes{
  _=cmd.Process.Kill();_=cmd.Wait()
  return Event{},errors.New("SSH authentication journal output limit exceeded")
 }
 if err=cmd.Wait();err!=nil{return Event{},errors.New("host SSH journald query failed")}
 return FindSessionEvent(data,peerPID,expect,reader)
}

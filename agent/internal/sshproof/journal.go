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

const maxJournalEvidenceBytes=4<<20

// MatchOneFromJournal searches for EXACTLY one matching trusted sshd event.
// The bytes must come directly from the root helper's journalctl invocation.
// JSON submitted by an SSH user or remote API is not a trusted journal source.
func MatchOneFromJournal(journal []byte, expected Challenge)(Event,error){
 var found Event
 if len(journal)==0||len(journal)>maxJournalEvidenceBytes{
  return found,errors.New("journal unavailable or too large")
 }
 scanner:=bufio.NewScanner(bytes.NewReader(journal))
 scanner.Buffer(make([]byte,1024),32768)
 count:=0
 for scanner.Scan(){
  line:=bytes.TrimSpace(scanner.Bytes())
  if len(line)==0{continue}
  event,err:=ParseTrustedJournal(line)
  if err!=nil{continue} // ignore non-SSH and untrusted records
  if Match(event,expected)!=nil{continue}
  count++
  if count>1{return Event{},errors.New("ambiguous duplicate SSH accepted events")}
  found=event
 }
 if err:=scanner.Err();err!=nil{return Event{},err}
 if count!=1{return Event{},errors.New("no matching root-observed publickey SSH event")}
 return found,nil
}

// ReadRootJournal only queries local journald with fixed, non-shell arguments.
// It cannot by itself prove that an external challenge was submitted from the
// same authenticated SSH session: process-lineage binding is still required.
func ReadRootJournal(ctx context.Context,expected Challenge)(Event,error){
 if os.Geteuid()!=0{return Event{},errors.New("root-only SSH journal verification")}
 if expected.IssuedAt.IsZero()||expected.ExpiresAt.IsZero()||
  !expected.ExpiresAt.After(expected.IssuedAt)||
  expected.ExpiresAt.Sub(expected.IssuedAt)>5*time.Minute{
  return Event{},errors.New("invalid challenge window")
 }
 now:=time.Now()
 if now.Before(expected.IssuedAt)||!now.Before(expected.ExpiresAt){
  return Event{},errors.New("challenge not active")
 }
 deadline,cancel:=context.WithTimeout(ctx,6*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(deadline,"/usr/bin/journalctl",
  "--quiet","--no-pager","--output=json",
  "--since=@"+strconv.FormatInt(expected.IssuedAt.Unix(),10),
  "--until=@"+strconv.FormatInt(now.Unix()+1,10),
  "--identifier=sshd","--identifier=sshd-session")
 cmd.Stderr=io.Discard
 stdout,err:=cmd.StdoutPipe()
 if err!=nil{return Event{},errors.New("cannot open local SSH journal")}
 if err=cmd.Start();err!=nil{return Event{},errors.New("journalctl unavailable")}
 data,err:=io.ReadAll(io.LimitReader(stdout,maxJournalEvidenceBytes+1))
 if err!=nil||len(data)>maxJournalEvidenceBytes{
  _=cmd.Process.Kill()
  _=cmd.Wait()
  return Event{},errors.New("SSH journal read limit exceeded")
 }
 if err=cmd.Wait();err!=nil{return Event{},errors.New("local SSH journal query failed")}
 return MatchOneFromJournal(data,expected)
}

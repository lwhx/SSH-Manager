// Package sshproof validates server-observed SSH public-key authentication
// evidence. It does NOT unlock SSH authentication changes or accept arbitrary
// client-supplied SSH_USER_AUTH files.
package sshproof

import (
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "regexp"
 "strconv"
 "strings"
 "time"
)

// Require an EXACT OpenSSH accepted ED25519 authentication message. No suffixes
// or prefix-injected forged log lines are accepted.
var accepted = regexp.MustCompile("^Accepted publickey for ([a-z_][a-z0-9_-]{0,31}[$]?) from ([0-9a-fA-F:.]+) port ([0-9]{1,5}) ssh2: ED25519 SHA256:([A-Za-z0-9+/]{43})$")
var unpaddedSHA256 = regexp.MustCompile("^SHA256:[A-Za-z0-9+/]{43}$")

type Event struct {
 User string `json:"user"`
 ClientIP string `json:"client_ip"`
 ClientPort uint16 `json:"client_port"`
 Fingerprint string `json:"fingerprint"`
 Timestamp time.Time `json:"timestamp"`
 PID int `json:"pid"`
 SourcePath string `json:"source_path"`
}
type JournalMessage struct {
 Message string `json:"MESSAGE"`
 Exe string `json:"_EXE"`
 UID string `json:"_UID"`
 PID string `json:"_PID"`
 TimeUS string `json:"__REALTIME_TIMESTAMP"`
}

func trustedSSHDExecutable(path string)bool {
 switch path {
 case "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session",
  "/usr/libexec/openssh/sshd-session", "/usr/libexec/sshd-session":
  return true
 default:return false
 }
}
func parseAccepted(message string)(Event,error){
 var result Event
 if len(message)>1024{return result,errors.New("overlong auth event")}
 m:=accepted.FindStringSubmatch(strings.TrimSpace(message))
 if len(m)!=5{return result,errors.New("not a supported accepted Ed25519 publickey event")}
 ip:=net.ParseIP(m[2])
 port,err:=strconv.Atoi(m[3])
 if err!=nil||port<1||port>65535||ip==nil{return result,errors.New("invalid accepted TCP connection tuple")}
 fingerprint:="SHA256:"+m[4]
 if !unpaddedSHA256.MatchString(fingerprint){return result,errors.New("invalid SHA256 fingerprint")}
 return Event{User:m[1],ClientIP:ip.String(),ClientPort:uint16(port),Fingerprint:fingerprint},nil
}

// ParseMessage is for syntax-only unit/integration tests. It is NOT trusted.
func ParseMessage(message string)(Event,error){return parseAccepted(message)}

// ParseTrustedJournal accepts journalctl's trusted _EXE, _UID, _PID fields
// but the caller MUST obtain this JSON directly from the root helper's local
// journalctl command. Untrusted JSON is NOT a proof of SSH authentication.
func ParseTrustedJournal(line []byte)(Event,error){
 var result Event
 if len(line)==0||len(line)>32768{return result,errors.New("unacceptable journald record size")}
 var record JournalMessage
 if err:=json.Unmarshal(line,&record);err!=nil{return result,err}
 if !trustedSSHDExecutable(record.Exe)||record.UID!="0"{
  return result,errors.New("journal record lacks trusted SSH daemon and UID provenance")
 }
 pid,err:=strconv.Atoi(record.PID)
 if err!=nil||pid<1{return result,errors.New("invalid sshd process ID")}
 microseconds,err:=strconv.ParseInt(record.TimeUS,10,64)
 if err!=nil||microseconds<=0{return result,errors.New("invalid journal timestamp")}
 result,err=parseAccepted(record.Message)
 if err!=nil{return result,err}
 result.Timestamp=time.UnixMicro(microseconds).UTC()
 result.PID=pid
 result.SourcePath=record.Exe
 return result,nil
}

type Challenge struct {
 LoginUser string
 KeyFingerprint string
 ClientIP string
 ClientPort uint16
 IssuedAt time.Time
 ExpiresAt time.Time
}
// Match requires network tuple to come from a trusted live SSH session,
// NOT an unchecked SSH_CONNECTION environment variable supplied by a client.
func Match(event Event,want Challenge)error{
 if want.LoginUser==""||want.LoginUser!=event.User{
  return errors.New("authenticated login user mismatch")
 }
 if !unpaddedSHA256.MatchString(want.KeyFingerprint)||want.KeyFingerprint!=event.Fingerprint{
  return errors.New("authenticated daily key mismatch")
 }
 a,b:=net.ParseIP(event.ClientIP),net.ParseIP(want.ClientIP)
 if a==nil||b==nil||!a.Equal(b)||want.ClientPort==0||want.ClientPort!=event.ClientPort{
  return errors.New("SSH connection tuple mismatch")
 }
 if event.Timestamp.IsZero()||want.IssuedAt.IsZero()||want.ExpiresAt.IsZero()||
  !want.ExpiresAt.After(want.IssuedAt)||want.ExpiresAt.Sub(want.IssuedAt)>5*time.Minute{
  return errors.New("invalid SSH verification time window")
 }
 if event.Timestamp.Before(want.IssuedAt)||!event.Timestamp.Before(want.ExpiresAt){
  return fmt.Errorf("SSH auth event outside challenge time window")
 }
 return nil
}

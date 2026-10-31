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

var accepted = regexp.MustCompile(`^Accepted publickey for ([a-z_][a-z0-9_-]{0,31}[$]?) from ([0-9a-fA-F:.]+) port ([0-9]{1,5}) ssh2: ED25519 SHA256:([A-Za-z0-9+/]{43}) // Package sshproof validates server-observed SSH public-key authentication
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

var accepted = regexp.MustCompile(`^Accepted publickey for ([a-z_][a-z0-9_-]{0,31}[$]?) from ([0-9a-fA-F:.]+) port ([0-9]{1,5}) ssh2: ED25519 SHA256:([A-Za-z0-9+/]{43}))
var unpaddedSHA256 = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

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

// This list is a conservative allowlist, NOT a fuzzy substring search.
// New OpenSSH layouts must be reviewed and explicitly added.
func trustedSSHDExecutable(path string)bool{
 switch path {
 case "/usr/sbin/sshd","/usr/lib/openssh/sshd-session",
  "/usr/libexec/openssh/sshd-session","/usr/libexec/sshd-session":
  return true
 default: return false
 }
}
func parseAccepted(message string)(Event,error){
 var result Event
 if len(message)>1024{return result,errors.New("overlong auth event")}
 match:=accepted.FindStringSubmatch(strings.TrimSpace(message))
 if len(match)!=5{return result,errors.New("not a supported accepted Ed25519 publickey event")}
 ip:=net.ParseIP(match[2])
 port,err:=strconv.Atoi(match[3])
 if err!=nil||port<1||port>65535||ip==nil{return result,errors.New("invalid accepted TCP connection tuple")}
 fp:="SHA256:"+match[4]
 if !unpaddedSHA256.MatchString(fp){return result,errors.New("invalid SHA256 fingerprint")}
 return Event{User:match[1],ClientIP:ip.String(),ClientPort:uint16(port),Fingerprint:fp},nil
}

// ParseMessage is intentionally ONLY a syntax parser for unit/integration
// tests. Never trust its output as an auth proof: no syslog provenance exists.
func ParseMessage(message string)(Event,error){return parseAccepted(message)}

// ParseTrustedJournal checks journald reserved metadata from a trusted source.
// Its argument MUST be obtained directly by the root helper from local
// journalctl --output=json; caller-supplied JSON is NOT an authentication proof.
// Parsing /var/log/auth.log or user-provided SSH_USER_AUTH is insufficient.
func ParseTrustedJournal(line []byte)(Event,error){
 var event Event
 if len(line)==0||len(line)>32768{return event,errors.New("unacceptable journald record size")}
 var record JournalMessage
 if err:=json.Unmarshal(line,&record);err!=nil{return event,err}
 if !trustedSSHDExecutable(record.Exe)||record.UID!="0"{
  return event,errors.New("journald record lacks trusted sshd executable and root UID provenance")
 }
 pid,err:=strconv.Atoi(record.PID)
 if err!=nil||pid<1{return event,errors.New("invalid sshd process identifier")}
 usec,err:=strconv.ParseInt(record.TimeUS,10,64)
 if err!=nil||usec<=0{return event,errors.New("invalid journald realtime clock")}
 event,err=parseAccepted(record.Message)
 if err!=nil{return event,err}
 event.Timestamp=time.UnixMicro(usec).UTC()
 event.PID=pid
 event.SourcePath=record.Exe
 return event,nil
}

type Challenge struct {
 LoginUser string
 KeyFingerprint string
 ClientIP string
 ClientPort uint16
 IssuedAt time.Time
 ExpiresAt time.Time
}
// Match checks log event fields against a separately authenticated challenge.
// The TCP tuple MUST come from a trusted live SSH session or verified socket,
// NEVER from an unchecked caller-provided SSH_CONNECTION variable.
func Match(event Event,expected Challenge)error{
 if expected.LoginUser==""||expected.LoginUser!=event.User{
  return errors.New("authenticated login user mismatch")
 }
 if !unpaddedSHA256.MatchString(expected.KeyFingerprint)||event.Fingerprint!=expected.KeyFingerprint{
  return errors.New("authenticated public key mismatch")
 }
 actualIP,expectedIP:=net.ParseIP(event.ClientIP),net.ParseIP(expected.ClientIP)
 if actualIP==nil||expectedIP==nil||!actualIP.Equal(expectedIP)||expected.ClientPort==0||
  event.ClientPort!=expected.ClientPort{
  return errors.New("authenticated SSH session network tuple mismatch")
 }
 if event.Timestamp.IsZero()||expected.IssuedAt.IsZero()||expected.ExpiresAt.IsZero()||
  !expected.ExpiresAt.After(expected.IssuedAt)||expected.ExpiresAt.Sub(expected.IssuedAt)>5*time.Minute{
  return errors.New("invalid challenge time window")
 }
 if event.Timestamp.Before(expected.IssuedAt)||
  !event.Timestamp.Before(expected.ExpiresAt){
  return fmt.Errorf("SSH auth event outside single-use challenge window")
 }
 return nil
}

package sshproof

import (
 "encoding/json"
 "fmt"
 "strings"
 "testing"
 "time"
)
const fingerprint="SHA256:WqyC1TNJwaA73QFZwyV9a7G2SpMUEMDwVZ7OEWHsMmg"
const acceptedMessage="Accepted publickey for root from 203.0.113.9 port 52133 ssh2: ED25519 "+fingerprint
func TestTrustedJournalAndMatching(t *testing.T){
 started:=time.Unix(1793440000,0)
 data,_:=json.Marshal(map[string]string{
  "MESSAGE":acceptedMessage,"_EXE":"/usr/sbin/sshd","_UID":"0","_PID":"1548","_TRANSPORT":"syslog","_TRANSPORT":"syslog",
  "__REALTIME_TIMESTAMP":fmt.Sprint(started.Add(time.Second*7).UnixMicro()),
 })
 got,err:=ParseTrustedJournal(data)
 if err!=nil{t.Fatal(err)}
 want:=Challenge{LoginUser:"root",KeyFingerprint:fingerprint,ClientIP:"203.0.113.9",
  ClientPort:52133,IssuedAt:started,ExpiresAt:started.Add(time.Minute*5)}
 if err:=Match(got,want);err!=nil{t.Fatal(err)}
 if got.PID!=1548||got.SourcePath!="/usr/sbin/sshd"{t.Fatal("missing trusted source metadata")}
}
func TestRejectsSpoofedOrIncompleteJournal(t *testing.T){
 original:=map[string]string{
  "MESSAGE":acceptedMessage,"_EXE":"/usr/sbin/sshd","_UID":"0","_PID":"1548",
  "__REALTIME_TIMESTAMP":"1793440007000000",
 }
 for name,patch:=range map[string]func(map[string]string){
  "fake executable":func(m map[string]string){m["_EXE"]="/usr/bin/logger"},
  "stdout parent PID":func(m map[string]string){m["_TRANSPORT"]="stdout"},
  "kernel transport":func(m map[string]string){m["_TRANSPORT"]="kernel"},
  "missing transport":func(m map[string]string){delete(m,"_TRANSPORT")},
  "wrong uid":func(m map[string]string){m["_UID"]="1000"},
  "missing pid":func(m map[string]string){delete(m,"_PID")},
  "no log time":func(m map[string]string){delete(m,"__REALTIME_TIMESTAMP")},
  "password login":func(m map[string]string){m["MESSAGE"]=strings.Replace(acceptedMessage,"publickey","password",1)},
  "rsa login":func(m map[string]string){m["MESSAGE"]=strings.Replace(acceptedMessage,"ED25519","RSA",1)},
  "wrong SSH result":func(m map[string]string){m["MESSAGE"]=strings.Replace(acceptedMessage,"Accepted","Failed",1)},
  "fake prefix":func(m map[string]string){m["MESSAGE"]="noise "+acceptedMessage},
 }{
  t.Run(name,func(t *testing.T){
   record:=map[string]string{};for k,v:=range original{record[k]=v}
   patch(record)
   payload,_:=json.Marshal(record)
   if _,err:=ParseTrustedJournal(payload);err==nil{t.Fatalf("spoofed journal accepted: %s",name)}
  })
 }
}
func TestRejectsReplayDifferentConnectionOrChallenge(t *testing.T){
 start:=time.Unix(1793440000,0)
 event,err:=ParseMessage(acceptedMessage)
 if err!=nil{t.Fatal(err)}
 event.Timestamp=start.Add(2*time.Second)
 candidate:=Challenge{LoginUser:"root",KeyFingerprint:fingerprint,ClientIP:"203.0.113.9",
  ClientPort:52133,IssuedAt:start,ExpiresAt:start.Add(5*time.Minute)}
 for name,mutate:=range map[string]func(*Challenge){
  "wrong user":func(c *Challenge){c.LoginUser="ubuntu"},
  "wrong IP":func(c *Challenge){c.ClientIP="198.51.100.8"},
  "wrong port":func(c *Challenge){c.ClientPort=52134},
  "wrong key":func(c *Challenge){c.KeyFingerprint="SHA256:"+strings.Repeat("a",43)},
  "invalid window":func(c *Challenge){c.ExpiresAt=start.Add(time.Minute*6)},
  "issued after login":func(c *Challenge){c.IssuedAt=start.Add(time.Second*5)},
  "expired":func(c *Challenge){c.ExpiresAt=start.Add(time.Second)},
 }{
  t.Run(name,func(t *testing.T){
   test:=candidate;mutate(&test)
   if err:=Match(event,test);err==nil{t.Fatal("accepted mismatching evidence")}
  })
 }
}
func TestIPv6AndHostileLogText(t *testing.T){
 line:="Accepted publickey for ubuntu from 2001:db8::2 port 44321 ssh2: ED25519 "+fingerprint
 if e,err:=ParseMessage(line);err!=nil||e.ClientIP!="2001:db8::2"{t.Fatalf("ipv6 rejection: %+v %v",e,err)}
 for _,value:=range []string{"Accepted password for root from 203.0.113.9 port 1 ssh2",
  acceptedMessage+"\n"+acceptedMessage,
  "Accepted publickey for invalid user root from 203.0.113.9 port 52133 ssh2: ED25519 "+fingerprint}{
  if _,err:=ParseMessage(value);err==nil{t.Fatalf("accepted invalid authentication log: %q",value)}
 }
}

func TestNativeJournalTransportAcceptedWithoutStdoutFallback(t *testing.T){
 now:=time.Unix(1793440000,0)
 for _,transport:=range []string{"syslog","journal"}{
  raw,_:=json.Marshal(map[string]string{
   "MESSAGE":acceptedMessage,"_EXE":"/usr/sbin/sshd","_UID":"0",
   "_PID":"1548","_TRANSPORT":transport,"__REALTIME_TIMESTAMP":fmt.Sprint(now.UnixMicro()),
  })
  if _,err:=ParseTrustedJournal(raw);err!=nil{t.Fatalf("%s rejected: %v",transport,err)}
 }
}

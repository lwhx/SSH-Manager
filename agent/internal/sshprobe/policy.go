// Package sshprobe parses effective OpenSSH settings without changing them.
// The future root Helper must run sshd -t and sshd -T -C with a validated
// connection context before relying on this policy.
package sshprobe

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "strings"
)
type Effective struct {
 PublicKeyAuthentication bool
 PasswordAuthentication bool
 KeyboardInteractive bool
 PermitRootLogin string
 AuthorizedKeysFile []string
 AuthenticationMethods string
 Revision string
}
func ParseEffective(stdout string)(Effective,error){
 var p Effective
 if len(stdout)==0||len(stdout)>128*1024{return p,errors.New("invalid sshd effective output size")}
 values:=map[string]string{}
 for _,line:=range strings.Split(stdout,"\n"){
  fields:=strings.Fields(line)
  if len(fields)==0{continue}
  name:=strings.ToLower(fields[0])
  value:=strings.Join(fields[1:]," ")
  if value==""{return p,fmt.Errorf("empty effective setting: %s",name)}
  if _,exists:=values[name];exists{return p,fmt.Errorf("duplicate sshd effective setting: %s",name)}
  values[name]=value
 }
 required:=[]string{"pubkeyauthentication","passwordauthentication","kbdinteractiveauthentication","permitrootlogin","authorizedkeysfile","authenticationmethods"}
 for _,name:=range required{
  if _,ok:=values[name];!ok{return p,fmt.Errorf("missing effective setting: %s",name)}
 }
 parseBool:=func(name string)(bool,error){
  switch values[name]{
  case "yes":return true,nil
  case "no":return false,nil
  default:return false,fmt.Errorf("unexpected %s=%s",name,values[name])
  }
 }
 var err error
 if p.PublicKeyAuthentication,err=parseBool("pubkeyauthentication");err!=nil{return p,err}
 if p.PasswordAuthentication,err=parseBool("passwordauthentication");err!=nil{return p,err}
 if p.KeyboardInteractive,err=parseBool("kbdinteractiveauthentication");err!=nil{return p,err}
 p.PermitRootLogin=values["permitrootlogin"]
 p.AuthorizedKeysFile=strings.Fields(values["authorizedkeysfile"])
 p.AuthenticationMethods=values["authenticationmethods"]
 digest:=sha256.Sum256([]byte(stdout))
 p.Revision=hex.EncodeToString(digest[:])
 return p,nil
}
// Eligibility checks only this sshd -T context, NOT a real SSH login.
func (p Effective) DailyKeyEligibility(loginUser string)error{
 if !p.PublicKeyAuthentication{return errors.New("public key authentication disabled")}
 if loginUser=="root"&&p.PermitRootLogin=="no"{return errors.New("root SSH login disabled")}
 if p.AuthenticationMethods!="any"&&p.AuthenticationMethods!="publickey"{
  return fmt.Errorf("additional authentication methods required: %s",p.AuthenticationMethods)
 }
 if len(p.AuthorizedKeysFile)!=1||p.AuthorizedKeysFile[0]!=".ssh/authorized_keys"{
  return fmt.Errorf("unsupported AuthorizedKeysFile: %v",p.AuthorizedKeysFile)
 }
 switch p.PermitRootLogin{
 case "yes","no","prohibit-password","forced-commands-only":
 default:return fmt.Errorf("unexpected PermitRootLogin=%s",p.PermitRootLogin)
 }
 if loginUser=="root"&&p.PermitRootLogin=="forced-commands-only"{return errors.New("root restricted to forced commands")}
 return nil
}

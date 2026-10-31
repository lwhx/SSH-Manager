// ssh-manager-prove runs INSIDE a new SSH public-key-authenticated session.
// It reads the five-minute challenge token from stdin (never argv or env) and
// makes one local Unix socket request. It cannot change SSH configuration.
package main

import (
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net"
 "os"
 "regexp"
 "strings"
 "time"
)
const socket="/run/ssh-manager-proof/proof.sock"
var uuid=regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
type response struct{
 OK bool `json:"ok"`
 Code string `json:"code"`
}
func run(verificationID,nonce string)error{
 if !uuid.MatchString(verificationID)||len(nonce)!=43{
  return errors.New("invalid verification challenge")
 }
 conn,err:=net.DialTimeout("unix",socket,3*time.Second)
 if err!=nil{return errors.New("local SSH proof socket unavailable")}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(12*time.Second))
 request,_:=json.Marshal(map[string]string{"verification_id":verificationID,"nonce":nonce})
 if _,err=conn.Write(request);err!=nil{return errors.New("cannot send local SSH proof")}
 if u,ok:=conn.(*net.UnixConn);ok{_ = u.CloseWrite()}
 var result response
 if err=json.NewDecoder(io.LimitReader(conn,2048)).Decode(&result);err!=nil{
  return errors.New("no valid root-helper proof response")
 }
 if !result.OK||result.Code!="SIGNED_PROOF_QUEUED"{
  return fmt.Errorf("SSH login proof not accepted: %s",result.Code)
 }
 return nil
}
func main(){
 id:=flag.String("id","","5-minute SSH Manager verification UUID")
 flag.Parse()
 if flag.NArg()!=0{fmt.Fprintln(os.Stderr,"unexpected positional arguments");os.Exit(2)}
 // Keep the nonce out of process argument lists, logs and environment.
 data,err:=io.ReadAll(io.LimitReader(os.Stdin,128))
 if err!=nil||len(data)>127{
  fmt.Fprintln(os.Stderr,"invalid challenge input");os.Exit(2)
 }
 nonce:=strings.TrimSpace(string(data))
 if err:=run(*id,nonce);err!=nil{
  fmt.Fprintln(os.Stderr,err.Error())
  os.Exit(1)
 }
 fmt.Println("SSH public-key login was locally observed. Awaiting control-plane proof verification.")
}

package main

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "log"
 "net/http"
 "os"
 "os/signal"
 "path/filepath"
 "strings"
 "syscall"
 "time"
)

type Config struct {
 Gateway string `json:"gateway"`
 NodeID string `json:"node_id"`
 DeviceKey string `json:"device_key"`
 CommandPublicKey string `json:"command_public_key"`
 StateDir string `json:"state_dir"`
}
type Command struct {
 V int `json:"v"`
 ID string `json:"id"`
 NodeID string `json:"node_id"`
 Action string `json:"action"`
 Actor string `json:"actor"`
 IssuedAt int64 `json:"issued_at"`
 ExpiresAt int64 `json:"expires_at"`
 ExpectedRevision string `json:"expected_revision"`
 Payload json.RawMessage `json:"payload"`
}
type SignedCommand struct {
 Command string `json:"command"`
 Signature string `json:"signature"`
}
type Agent struct { config Config; secret ed25519.PrivateKey; http *http.Client }
func decode(s string)([]byte,error){return base64.RawURLEncoding.DecodeString(s)}
func encode(b []byte)string{return base64.RawURLEncoding.EncodeToString(b)}
func (a *Agent) request(ctx context.Context,path string,body any)([]byte,error){
 raw,err:=json.Marshal(body);if err!=nil{return nil,err}
 u:=strings.TrimRight(a.config.Gateway,"/")+path
 if !strings.HasPrefix(u,"https://"){return nil,errors.New("agent gateway must use HTTPS")}
 req,err:=http.NewRequestWithContext(ctx,"POST",u,bytes.NewReader(raw));if err!=nil{return nil,err}
 now:=time.Now().Unix()
 nonce:=make([]byte,24);if _,err=rand.Read(nonce);err!=nil{return nil,err}
 digest:=sha256.Sum256(raw)
 message:=fmt.Sprintf("POST\n%s\n%d\n%s\n%s",path,now,encode(nonce),hex.EncodeToString(digest[:]))
 req.Header.Set("Content-Type","application/json")
 req.Header.Set("X-Node-Id",a.config.NodeID)
 req.Header.Set("X-Device-Timestamp",fmt.Sprint(now))
 req.Header.Set("X-Device-Nonce",encode(nonce))
 req.Header.Set("X-Device-Signature",encode(ed25519.Sign(a.secret,[]byte(message))))
 res,err:=a.http.Do(req);if err!=nil{return nil,err};defer res.Body.Close()
 b,err:=io.ReadAll(io.LimitReader(res.Body,65536));if err!=nil{return nil,err}
 if res.StatusCode!=200{return nil,fmt.Errorf("gateway status %d: %s",res.StatusCode,b)}
 return b,nil
}
func readConfig(path string)(Config,ed25519.PrivateKey,error){
 b,err:=os.ReadFile(path);if err!=nil{return Config{},nil,err}
 var c Config
 if err=json.Unmarshal(b,&c);err!=nil{return c,nil,err}
 pk,err:=decode(c.DeviceKey);if err!=nil{return c,nil,err}
 if len(pk)!=ed25519.PrivateKeySize{return c,nil,errors.New("invalid device private key")}
 return c,ed25519.PrivateKey(pk),nil
}
func (a *Agent) verify(s SignedCommand)(Command,error){
 var c Command
 pub,err:=decode(a.config.CommandPublicKey);if err!=nil{return c,err}
 sig,err:=decode(s.Signature);if err!=nil{return c,err}
 if len(pub)!=ed25519.PublicKeySize||!ed25519.Verify(ed25519.PublicKey(pub),[]byte(s.Command),sig){return c,errors.New("invalid control signature")}
 if err=json.Unmarshal([]byte(s.Command),&c);err!=nil{return c,err}
 now:=time.Now().Unix()
 if c.NodeID!=a.config.NodeID||c.V!=1||!operationID.MatchString(c.ID)||c.IssuedAt>now+10||c.ExpiresAt<=now||c.ExpiresAt>c.IssuedAt+60 {return c,errors.New("invalid or expired command")}
 if c.Action!="node.preflight"&&c.Action!="node.status"&&c.Action!="ssh.daily.install"{return c,errors.New("action not allowed")}
 return c,nil
}
func report(a *Agent,ctx context.Context,id,status,code string,detail any){
 _,err:=a.request(ctx,"/agent/v1/report",map[string]any{"operation_id":id,"status":status,"result_code":code,"detail":detail})
 if err!=nil{log.Printf("report failed for %s: %v",id,err)}
}
func (a *Agent) handle(ctx context.Context,s SignedCommand){
 c,err:=a.verify(s);if err!=nil{log.Printf("rejected command: %v",err);return}
 if err:=a.claimOperation(c);err!=nil{
  log.Printf("blocked duplicate/unsafe operation %s: %v",c.ID,err)
  return
 }
 switch c.Action{
 case "ssh.daily.install":
  // Deliberate safety lock: the independent privileged SSH helper is not ready.
  report(a,ctx,c.ID,"FAILED","SSH_HELPER_NOT_IMPLEMENTED",map[string]string{"message":"SSH write disabled until privileged helper and login verification are audited"})
 case "node.preflight":
  report(a,ctx,c.ID,"SUCCEEDED","READ_ONLY_DIAGNOSTIC",readOnlyPreflight())
 case "node.status":
  report(a,ctx,c.ID,"SUCCEEDED","TRANSPORT_ALIVE",map[string]string{"agent_version":"0.2.0"})
 default:
  report(a,ctx,c.ID,"FAILED","ACTION_NOT_SUPPORTED",nil)
 }
}
func run(ctx context.Context,path string)error {
 c,key,err:=readConfig(path);if err!=nil{return err}
 a:=&Agent{config:c,secret:key,http:&http.Client{Timeout:12*time.Second}}
 go a.websocketLoop(ctx)
 ticker:=time.NewTicker(10*time.Second);defer ticker.Stop()
 for {
   select{case <-ctx.Done():return nil;default:}
   heartbeatCtx,cancel:=context.WithTimeout(ctx,10*time.Second)
   _,err=a.request(heartbeatCtx,"/agent/v1/heartbeat",map[string]string{"agent_version":"0.1.0","os_id":"linux"})
   cancel()
   if err!=nil{log.Printf("heartbeat: %v",err)}
   pollCtx,cancel:=context.WithTimeout(ctx,10*time.Second)
   raw,err:=a.request(pollCtx,"/agent/v1/poll",map[string]string{})
   cancel()
   if err==nil {
     var value struct{Command string `json:"command"`; Signature string `json:"signature"`}
     if json.Unmarshal(raw,&value)==nil&&value.Command!=""{a.handle(ctx,SignedCommand(value))}
   }else{log.Printf("poll: %v",err)}
   select{case <-ctx.Done():return nil;case <-ticker.C:}
 }
}
func pair(ctx context.Context,gateway,node,token,path string)error{
 if !strings.HasPrefix(gateway,"https://"){return errors.New("gateway must be HTTPS")}
 _,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{return err}
 body,_:=json.Marshal(map[string]string{"node_id":node,"token":token,"public_key":encode(private.Public().(ed25519.PublicKey))})
 req,err:=http.NewRequestWithContext(ctx,"POST",strings.TrimRight(gateway,"/")+"/agent/v1/pair",bytes.NewReader(body));if err!=nil{return err}
 req.Header.Set("Content-Type","application/json")
 client:=&http.Client{Timeout:15*time.Second}
 res,err:=client.Do(req);if err!=nil{return err};defer res.Body.Close()
 b,_:=io.ReadAll(io.LimitReader(res.Body,8192))
 if res.StatusCode!=201{return fmt.Errorf("pairing failed HTTP %d: %s",res.StatusCode,b)}
 var result struct{CommandSigningPublicKey string `json:"command_signing_public_key"`}
 if err=json.Unmarshal(b,&result);err!=nil{return err}
 public,err:=decode(result.CommandSigningPublicKey);if err!=nil||len(public)!=ed25519.PublicKeySize{return errors.New("invalid server command signing key")}
 conf:=Config{Gateway:gateway,NodeID:node,DeviceKey:encode(private),CommandPublicKey:result.CommandSigningPublicKey}
 content,_:=json.MarshalIndent(conf,"","  ")
 if err=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err}
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
 defer f.Close()
 if _,err=f.Write(content);err!=nil{return err}
 fmt.Println("Device paired. Config stored with mode 0600.");return nil
}
func main(){
 mode:=flag.String("mode","run","run or pair")
 config:=flag.String("config","/etc/ssh-manager/agent.json","agent config path")
 gateway:=flag.String("gateway","","HTTPS gateway URL (pair only)")
 node:=flag.String("node","","node UUID (pair only)")
 token:=flag.String("token","","short-lived pairing token (pair only)")
 flag.Parse()
 ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGTERM,syscall.SIGINT);defer stop()
 var err error
 switch *mode {case "run":err=run(ctx,*config);case "pair":
  if *gateway==""||*node==""||*token==""{log.Fatal("pair requires gateway, node, token")}
  err=pair(ctx,*gateway,*node,*token,*config)
 default:err=errors.New("unknown mode")}
 if err!=nil{log.Fatal(err)}
}

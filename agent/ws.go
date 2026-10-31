package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "log"
 "net/http"
 "net/url"
 "strings"
 "time"

 "github.com/gorilla/websocket"
)

// WebSocket is outbound-only; the HTTPS poller remains active independently.
// Both paths deliver exactly the same signed, scope-checked commands.
func (a *Agent) websocketLoop(ctx context.Context) {
 for {
  if ctx.Err()!=nil{return}
  if err:=a.websocketSession(ctx);err!=nil&&ctx.Err()==nil{
   log.Printf("WSS disconnected; HTTPS polling remains active: %v",err)
  }
  select{case <-ctx.Done():return;case <-time.After(5*time.Second):}
 }
}
func (a *Agent) websocketSession(ctx context.Context)error{
 u,err:=url.Parse(a.config.Gateway)
 if err!=nil||u.Scheme!="https"||u.Host==""{return fmt.Errorf("gateway must be HTTPS")}
 u.Scheme="wss";u.Path="/agent/v1/ws";u.RawQuery="";u.Fragment=""
 nonce:=make([]byte,24)
 if _,err=rand.Read(nonce);err!=nil{return err}
 timestamp:=time.Now().Unix()
 digest:=sha256.Sum256([]byte{})
 message:=fmt.Sprintf("GET\n/agent/v1/ws\n%d\n%s\n%s",
  timestamp,encode(nonce),hex.EncodeToString(digest[:]))
 headers:=http.Header{}
 headers.Set("X-Node-Id",a.config.NodeID)
 headers.Set("X-Device-Timestamp",fmt.Sprint(timestamp))
 headers.Set("X-Device-Nonce",encode(nonce))
 headers.Set("X-Device-Signature",encode(ed25519.Sign(a.secret,[]byte(message))))
 dialer:=websocket.Dialer{Proxy:http.ProxyFromEnvironment,HandshakeTimeout:12*time.Second}
 conn,resp,err:=dialer.DialContext(ctx,u.String(),headers)
 if err!=nil{
  if resp!=nil{return fmt.Errorf("websocket HTTP %d: %w",resp.StatusCode,err)}
  return err
 }
 defer conn.Close()
 done:=make(chan struct{})
 defer close(done)
 go func(){
  ticker:=time.NewTicker(25*time.Second)
  defer ticker.Stop()
  for{
   select{
   case <-ctx.Done():_ = conn.Close();return
   case <-done:return
   case <-ticker.C:
    if err:=conn.WriteMessage(websocket.TextMessage,[]byte("ping"));err!=nil{
     _ = conn.Close();return
    }
   }
  }
 }()
 _ = conn.SetReadDeadline(time.Now().Add(85*time.Second))
 for{
  kind,data,err:=conn.ReadMessage();if err!=nil{return err}
  _ = conn.SetReadDeadline(time.Now().Add(85*time.Second))
  if kind!=websocket.TextMessage||strings.TrimSpace(string(data))=="pong"{continue}
  if len(data)>16384{log.Print("ignored oversized WSS frame");continue}
  var signed SignedCommand
  if json.Unmarshal(data,&signed)!=nil||signed.Command==""{
   log.Print("ignored malformed WSS payload");continue
  }
  a.handle(ctx,signed)
 }
}

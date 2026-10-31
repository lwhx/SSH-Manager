package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
)

var operationID = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
var errAlreadyClaimed = errors.New("operation already received")

// Persist the receipt before execution so WSS + polling or a process restart
// never replays a signed command. The future root helper needs its OWN journal.
func (a *Agent) claimOperation(cmd Command)error{
 if !operationID.MatchString(cmd.ID){return errors.New("invalid operation ID")}
 dir,err:=a.operationReceiptsDir()
 if err!=nil{return err}
 path:=filepath.Join(dir,cmd.ID+".json")
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if errors.Is(err,os.ErrExist){return errAlreadyClaimed}
 if err!=nil{return err}
 document,_:=json.Marshal(map[string]any{"operation_id":cmd.ID,"node_id":cmd.NodeID,"action":cmd.Action,"issued_at":cmd.IssuedAt})
 if _,err=f.Write(document);err!=nil{_ = f.Close();return err}
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 if err=f.Close();err!=nil{return err}
 d,err:=os.Open(dir);if err!=nil{return err}
 defer d.Close()
 if err=d.Sync();err!=nil{return fmt.Errorf("sync receipt directory: %w",err)}
 return nil
}

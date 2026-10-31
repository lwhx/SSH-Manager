package sshhelper

import (
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "syscall"
 "time"
)
type Journal struct{
 Directory string
}
func (j *Journal) Claim(id string)error{
 if j==nil||!uuidRE.MatchString(id){return errors.New("invalid journal or operation id")}
 if !filepath.IsAbs(j.Directory)||filepath.Clean(j.Directory)!=j.Directory{
  return errors.New("invalid journal path")
 }
 if err:=os.MkdirAll(j.Directory,0700);err!=nil{return err}
 st,err:=os.Lstat(j.Directory)
 if err!=nil||!st.IsDir()||st.Mode().Perm()&0077!=0{return errors.New("unsafe journal permissions")}
 if stat,ok:=st.Sys().(*syscall.Stat_t);!ok||stat.Uid!=uint32(os.Geteuid()){
  return errors.New("journal not owned by helper")
 }
 file,err:=os.OpenFile(filepath.Join(j.Directory,id+".json"),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if errors.Is(err,os.ErrExist){return errors.New("replayed signed operation")}
 if err!=nil{return err}
 payload,_:=json.Marshal(map[string]any{"operation_id":id,"reserved_at":time.Now().UTC().Format(time.RFC3339Nano)})
 if _,err=file.Write(payload);err!=nil{_ = file.Close();return err}
 if err=file.Sync();err!=nil{_ = file.Close();return err}
 if err=file.Close();err!=nil{return err}
 dir,err:=os.Open(j.Directory)
 if err!=nil{return err}
 defer dir.Close()
 return dir.Sync()
}

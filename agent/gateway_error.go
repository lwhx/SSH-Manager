package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "regexp"
)

// GatewayHTTPError preserves a safe, structured HTTP result. Never log a
// raw server response: it could include credentials or other sensitive data.
type GatewayHTTPError struct {
 Status int
 Code string
}
func (e *GatewayHTTPError)Error()string{
 return fmt.Sprintf("gateway HTTP %d: %s",e.Status,e.Code)
}
var gatewayCodeRE=regexp.MustCompile("^[A-Z][A-Z0-9_]{2,80}$")
func parseGatewayHTTPError(status int,body []byte)error{
 var value struct{Error string `json:"error"`}
 _=json.Unmarshal(body,&value)
 code:=value.Error
 if !gatewayCodeRE.MatchString(code){code="UNRECOGNIZED_GATEWAY_ERROR"}
 return &GatewayHTTPError{Status:status,Code:code}
}

// ONLY these documented gateway 409s mean this exact signed proof can
// never become VERIFIED. A 401, 403, 429, 5xx, network failure, or
// unknown 409 may be fixed later, so the proof stays queued for retry.
func permanentProofRejection(err error)(string,bool){
 var status *GatewayHTTPError
 if !errors.As(err,&status)||status.Status!=409{return "",false}
 switch status.Code{
 case "CHALLENGE_NOT_ACTIVE","CHALLENGE_CONTEXT_CHANGED","PROOF_ALREADY_USED_OR_CONTEXT_CHANGED":
  return status.Code,true
 default:return "",false
 }
}

package sshhelper

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
)
type ManualOperationReceipt struct{
 V int `json:"v"`
 NodeID string `json:"node_id"`
 OperationID string `json:"operation_id"`
 Action string `json:"action"`
 ResultCode string `json:"result_code"`
 ExpectedRevision string `json:"expected_revision"`
 DetailSHA256 string `json:"detail_sha256"`
 ExecutedAt int64 `json:"executed_at"`
}
type SignedManualReceipt struct{
 Payload string `json:"payload"`
 Signature string `json:"signature"`
}
// signManualReceipt binds an immutable operation ID, command revision and
// exact terminal output to the per-node Root proof key. The Agent only relays.
func (h *Handler) signManualReceipt(cmd Command, result Result)Result{
 if !result.OK||!isManualSSHAction(cmd.Action)||
  len(h.ProofSigningKey)!=ed25519.PrivateKeySize{
  return fail("ROOT_MANUAL_RECEIPT_UNAVAILABLE",nil)
 }
 raw,err:=json.Marshal(result.Detail)
 if err!=nil||len(raw)>4096{return fail("ROOT_MANUAL_RESULT_TOO_LARGE",nil)}
 digest:=sha256.Sum256(raw)
 receipt:=ManualOperationReceipt{
  V:1,NodeID:cmd.NodeID,OperationID:cmd.ID,Action:cmd.Action,
  ResultCode:result.Code,ExpectedRevision:cmd.ExpectedRevision,
  DetailSHA256:hex.EncodeToString(digest[:]),ExecutedAt:h.Clock().Unix(),
 }
 if receipt.ExecutedAt<cmd.IssuedAt-10||receipt.ExecutedAt>cmd.ExpiresAt{
  return fail("ROOT_MANUAL_RECEIPT_OUTSIDE_COMMAND_WINDOW",errors.New("execution outside signed command lifetime"))
 }
 body,err:=json.Marshal(receipt)
 if err!=nil{return fail("ROOT_MANUAL_RECEIPT_UNAVAILABLE",err)}
 signed:=SignedManualReceipt{Payload:string(body),
  Signature:base64.RawURLEncoding.EncodeToString(ed25519.Sign(h.ProofSigningKey,body))}
 result.Detail=map[string]any{"result":result.Detail,"root_receipt":signed}
 return result
}

import {ApiError} from "../../../packages/protocol/src/index";
/**
 * The independently signed daily key installation receipt cannot be
 * checked later unless the Owner has already pinned this node's Root key.
 * Reject before dispatching any SSH write.
 */
export async function requirePinnedRootForDailyInstall(
 db:D1Database,nodeId:string
):Promise<void>{
 const pinned=await db.prepare(
  "SELECT node_id FROM node_ssh_proof_keys WHERE node_id=?"
 ).bind(nodeId).first<{node_id:string}>();
 if(!pinned)throw new ApiError("NODE_ROOT_PROOF_KEY_NOT_PINNED",409);
}

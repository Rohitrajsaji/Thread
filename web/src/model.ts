export interface Thread {id:string; title:string; goal:string; status:string; track:number; base_sha:string; risk_reasons:string[]; credits_used:number; turns_used:number}
export interface Ticket {id:string; title:string; role:string; status:string; paths:string[]; depends_on:string[]; worktree_branch:string|null; result_sha:string|null}
export interface Checkpoint {id:string; stage:string; content_md:string; content_sha256:string; git_head_sha:string; status:string; permitted_next_stage:string|null; created_at:string; decided_at:string|null; waits_for_person:boolean}
export interface Note {id:string; checkpoint_id:string; target_type:string; file_path:string|null; line_or_section:string|null; comment:string}
export interface RuleEvidence {rule_id:string; test_nodeid:string|null; outcome:string; provenance:string}
export interface Verification {id:string; passed:boolean; commit_sha:string; rule_evidence:RuleEvidence[]; scorecard:Record<string,{passed:boolean; issues:string[]}>}
export interface Proposal {base_sha:string; head_sha:string; target_branch:string; diff:string}
export interface Snapshot {thread:Thread; tickets:Ticket[]; checkpoints:Checkpoint[]; annotations:Note[]; events:{id:number; type:string; created_at:string; payload_json:string}[]; verification_runs:Verification[]; integration?: object | null}
export class HttpError extends Error {constructor(public status:number, message:string){super(message)}}
export async function api<T>(path:string,body?:object):Promise<T>{
  const response=await fetch('/api/'+path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined})
  if(!response.ok){
    const message=await response.json().catch(()=>({}))
    throw new HttpError(response.status,typeof message.detail==='string'?message.detail:'Request failed ('+response.status+')')
  }
  return response.json()
}
export function label(text:string){return text.replace(/_/g,' ').replace(/([a-z])([A-Z])/g,'$1 $2').replace(/^./,c=>c.toUpperCase())}
export function date(text:string){return new Date(text).toLocaleString(undefined,{hour:'2-digit',minute:'2-digit',day:'numeric',month:'short'})}
export function taskPath(id:string){return '/tasks/'+encodeURIComponent(id)}
export function reviewPath(id:string,cp:string){return taskPath(id)+'/reviews/'+encodeURIComponent(cp)}
export function number(cp:Checkpoint,all:Checkpoint[]){return all.filter(c=>c.stage===cp.stage).sort((a,b)=>a.created_at.localeCompare(b.created_at)).findIndex(c=>c.id===cp.id)+1}
export function title(cp:Checkpoint,all:Checkpoint[]){return cp.stage==='diff'?'Final changes':label(cp.stage)+' '+number(cp,all)}
export const stageText:Record<string,[string,string]>={
  SpecDraft:['Drafting the specification','Developer · Continue in VS Code'],
  WaitingSpecApproval:['Specification needs review','Reviewer · Approve the scope or request changes'],
  PlanDraft:['Preparing the plan','Developer · Continue in VS Code'],
  WaitingPlanApproval:['Plan needs review','Reviewer · Review the tickets and their dependencies'],
  Executing:['Implementation in progress','Developer or worker · Check ticket progress'],
  Escalated:['Scope changed','Developer · Update the specification and plan'],
  PausedQuota:['Copilot usage limit reached','Account owner · Check the available allowance'],
  Verifying:['Verification in progress','Verifier · Check the proposed commit'],
  WaitingDiffApproval:['Changes need review','Reviewer · Inspect the diff and its verification evidence'],
  Merging:['Merge in progress','Thread · Waiting for the local merge result'],
  Completed:['Task complete','Review the decisions and recorded results']
}

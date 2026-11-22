import {Fragment, useEffect, useMemo, useRef, useState} from 'react'
import type {FormEvent} from 'react'
import {api, label, taskPath, title} from './model'
import type {Checkpoint, Proposal, Snapshot, Verification} from './model'

interface CommentTarget {
  target_type: 'section' | 'line'
  file_path?: string
  line_or_section?: string
}

interface ReviewProps {
  data: Snapshot
  cp: Checkpoint
  online: boolean
  refresh: () => Promise<void>
}

interface DocumentSection {
  heading: string
  level: number
  lines: string[]
}

function documentSections(markdown: string) {
  const sections: DocumentSection[] = [{heading: '', level: 0, lines: []}]
  let inCode = false
  for (const line of markdown.split(/\r?\n/)) {
    if (/^\s*```/.test(line)) inCode = !inCode
    const heading = inCode ? null : /^(#{1,6})\s+(.+)\s*$/.exec(line)
    if (heading) sections.push({heading: heading[2], level: Math.min(6, heading[1].length + 1), lines: []})
    else sections[sections.length - 1].lines.push(line)
  }
  return sections.filter(section => section.heading || section.lines.some(line => line.trim()))
}

function inlineMarkdown(value: string) {
  return value.split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g).map((part, index) => {
    if (part.startsWith('`') && part.endsWith('`')) return <code key={index}>{part.slice(1, -1)}</code>
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={index}>{part.slice(2, -2)}</strong>
    if (part.startsWith('*') && part.endsWith('*')) return <em key={index}>{part.slice(1, -1)}</em>
    return part
  })
}

function documentBlocks(lines: string[]) {
  const blocks: {kind: 'code' | 'list' | 'numbered' | 'paragraph'; lines: string[]}[] = []
  let code = false
  let separated = true
  for (const line of lines) {
    if (/^\s*```/.test(line)) {
      if (!code) blocks.push({kind: 'code', lines: []})
      code = !code
      separated = true
    } else if (code) {
      blocks[blocks.length - 1].lines.push(line)
    } else if (!line.trim()) {
      separated = true
    } else {
      const list = /^\s*([-*+] |\d+\. )(.+)$/.exec(line)
      const kind = !list ? 'paragraph' : /\d/.test(list[1][0]) ? 'numbered' : 'list'
      const previous = blocks[blocks.length - 1]
      if (separated || previous?.kind !== kind) blocks.push({kind, lines: []})
      blocks[blocks.length - 1].lines.push(list?.[2] ?? line.trim())
      separated = false
    }
  }
  return blocks.map(({kind, lines}, index) => {
    if (kind === 'code') return <pre key={index}><code>{lines.join('\n')}</code></pre>
    if (kind === 'paragraph') return <p key={index}>{inlineMarkdown(lines.join(' '))}</p>
    const List = kind === 'numbered' ? 'ol' : 'ul'
    return <List key={index}>{lines.map((line, item) => <li key={item}>{inlineMarkdown(line)}</li>)}</List>
  })
}

function Document({content, onComment}: {content: string; onComment?: (target: CommentTarget) => void}) {
  const sections = documentSections(content)
  if (!sections.length) return <p className="quiet">No document content was recorded.</p>
  return <div className="document">
    {sections.map(({heading, level, lines}, index) => {
      const Heading = (['h2', 'h3', 'h4', 'h5', 'h6'][level - 2] ?? 'h2') as 'h2' | 'h3' | 'h4' | 'h5' | 'h6'
      const section = heading || 'Introduction'
      return <section key={index} className="document-section">
        {(heading || onComment) && <div className="section-heading">
          <Heading>{inlineMarkdown(section)}</Heading>
          {onComment && <button type="button" className="text-button" onClick={() => onComment({target_type: 'section', line_or_section: section})}>
            <span className="sr-only">{section}: </span>Comment
          </button>}
        </div>}
        {documentBlocks(lines)}
      </section>
    })}
  </div>
}

function diffRows(text: string) {
  let oldPath = ''
  let newPath = ''
  let oldLine = 0
  let newLine = 0
  let inHunk = false
  return text.split('\n').map(line => {
    if (line.startsWith('diff --git ')) {
      inHunk = false
      oldPath = ''
      newPath = ''
    }
    if (!inHunk && line.startsWith('--- ')) oldPath = line.slice(4).replace(/^a\//, '')
    if (!inHunk && line.startsWith('+++ ')) newPath = line.slice(4).replace(/^b\//, '')
    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line)
    if (hunk) {
      inHunk = true
      oldLine = Number(hunk[1])
      newLine = Number(hunk[2])
    }
    const removed = inHunk && line.startsWith('-')
    const added = inHunk && line.startsWith('+')
    const context = inHunk && line.startsWith(' ')
    const before = removed || context ? oldLine++ : null
    const after = added || context ? newLine++ : null
    const path = removed ? oldPath : newPath
    const target = path && path !== '/dev/null' && (before !== null || after !== null)
      ? {target_type: 'line' as const, file_path: path, line_or_section: removed ? 'old:' + before : 'new:' + after}
      : undefined
    return {line, before, after, target, kind: removed ? 'removed' : added ? 'added' : context ? 'context' : 'diff-meta'}
  })
}

function UnifiedDiff({content, onComment}: {content: string; onComment?: (target: CommentTarget) => void}) {
  const rows = useMemo(() => diffRows(content), [content])
  if (!content.trim()) return <p className="quiet">No changes were recorded for this revision.</p>
  return <div className="diff-scroll" tabIndex={0} aria-label="Unified diff. Scroll horizontally for long lines.">
    <table className="diff-table">
      <thead><tr><th scope="col">Old</th><th scope="col">New</th><th scope="col">Change</th></tr></thead>
      <tbody>{rows.map(({line, before, after, kind, target}, index) => <tr key={index} className={kind}>
        <td>{before}</td>
        <td>{after}</td>
        <td>
          {target && onComment && <button
            className="line-comment"
            type="button"
            title="Comment on this line"
            aria-label={'Comment on ' + target.file_path + ', ' + target.line_or_section}
            onClick={() => onComment(target)}
          >+</button>}
          <code>{line || ' '}</code>
        </td>
      </tr>)}</tbody>
    </table>
  </div>
}

function Scorecard({run}: {run?: Verification}) {
  return <section className="panel">
    <h2>Verification evidence</h2>
    {!run ? <p className="quiet">No verification run is available for this revision.</p> : <>
      <p className={'result ' + (run.passed ? 'pass' : 'fail')}>{run.passed ? 'Verification passed' : 'Verification failed'}</p>
      {!!Object.keys(run.scorecard).length && <dl className="checks">
        {Object.entries(run.scorecard).map(([name, check]) => <Fragment key={name}>
          <dt>{label(name)}</dt>
          <dd><span className={check.passed ? 'pass' : 'fail'}>{check.passed ? 'Passed' : 'Failed'}</span>
            {!!check.issues.length && <ul>{check.issues.map((issue, index) => <li key={index}>{issue}</li>)}</ul>}
          </dd>
        </Fragment>)}
      </dl>}
      {!!run.rule_evidence.length && <ul className="rule-list">
        {run.rule_evidence.map((rule, index) => <li key={index}>
          <strong>{rule.rule_id}</strong><span className={rule.outcome === 'passed' ? 'pass' : 'fail'}>{label(rule.outcome)} · {label(rule.provenance)}</span>
          {rule.test_nodeid && <code>{rule.test_nodeid}</code>}
        </li>)}
      </ul>}
    </>}
  </section>
}

export function Review({data, cp, online, refresh}: ReviewProps) {
  const isDiff = cp.stage === 'diff'
  const merging = data.thread.status === 'Merging'
  const canComment = online && cp.status === 'pending' && !merging
  const canDecide = canComment && cp.waits_for_person && data.thread.status === 'Waiting' + label(cp.stage) + 'Approval'
  const canSubmitMerge = isDiff && online && cp.status === 'pending' && (canDecide || merging)
  const notes = data.annotations.filter(note => note.checkpoint_id === cp.id)
  const run = [...data.verification_runs].reverse().find(item => item.commit_sha === cp.git_head_sha)
  const ticket = isDiff
    ? [...data.tickets].reverse().find(item => item.status === 'done' && item.result_sha === cp.git_head_sha && item.worktree_branch)
    : undefined
  const ticketId = ticket?.id
  const [proposal, setProposal] = useState<Proposal | null>(null)
  const [proposalError, setProposalError] = useState('')
  const [proposalAttempt, retryProposal] = useState(0)
  const [target, setTarget] = useState<CommentTarget>({target_type: 'section'})
  const [comment, setComment] = useState('')
  const [reason, setReason] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const commentInput = useRef<HTMLTextAreaElement>(null)
  const endpoint = 'checkpoints/' + encodeURIComponent(cp.id)

  useEffect(() => {
    if (!ticketId || !canSubmitMerge) return
    let current = true
    setProposal(null)
    setProposalError('')
    void api<Proposal>('tickets/' + encodeURIComponent(ticketId) + '/diff').then(value => {
      if (current) setProposal(value)
    }, err => {
      if (current) setProposalError(err instanceof Error ? err.message : 'Proposal unavailable')
    })
    return () => { current = false }
  }, [canSubmitMerge, cp.git_head_sha, data.thread.base_sha, proposalAttempt, ticketId])

  const matchingProposal = proposal && proposal.head_sha === cp.git_head_sha &&
    proposal.base_sha === data.thread.base_sha && proposal.diff === cp.content_md
  const canMerge = matchingProposal && run?.passed && ticketId

  function selectTarget(value: CommentTarget) {
    setTarget(value)
    commentInput.current?.focus()
  }

  async function act(request: () => Promise<unknown>, success: string) {
    setPending(true)
    setMessage('')
    setError('')
    try {
      await request()
      setMessage(success)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The action could not be saved')
    } finally {
      await refresh()
      setPending(false)
    }
  }

  function addComment(event: FormEvent) {
    event.preventDefault()
    if (!canComment || pending || !comment.trim()) return
    void act(async () => {
      await api(endpoint + '/annotations', {...target, comment: comment.trim()})
      setComment('')
    }, 'Comment saved.')
  }

  function decide(decision: 'approved' | 'changes_requested') {
    if (!canDecide || pending || (decision === 'changes_requested' && !reason.trim())) return
    return act(() => api(endpoint + '/decide', {
      decision, reason: reason.trim(), content_sha256: cp.content_sha256, git_head_sha: cp.git_head_sha
    }), decision === 'approved' ? 'Approval saved.' : 'Changes requested.')
  }

  function merge() {
    if (!canSubmitMerge || pending || !canMerge || !ticketId || !proposal) return
    void act(() => api('tickets/' + encodeURIComponent(ticketId) + '/merge', {
      expected_head: cp.git_head_sha, expected_base: proposal.base_sha
    }), 'Worktree merged.')
  }

  const targetLabel = target.file_path ? target.file_path + ' · ' + target.line_or_section : target.line_or_section
  return <main id="content">
    <nav className="crumb" aria-label="Breadcrumb"><a href={taskPath(data.thread.id)}>Task overview</a></nav>
    <div className="review-header">
      <div><h1>{title(cp, data.checkpoints)}</h1><p className="meta">{data.thread.title}</p></div>
      <span className={'review-state ' + cp.status}>{label(cp.status)}</span>
    </div>
    <p className="meta revision">Reviewed {isDiff ? 'commit' : 'base revision'} <code title={cp.git_head_sha}>{cp.git_head_sha || 'Unavailable'}</code>
      {!isDiff && cp.content_sha256 && <> <span>·</span> Content hash <code title={cp.content_sha256}>{cp.content_sha256.slice(0, 12)}</code></>}
    </p>
    {cp.status === 'stale' && <p className="notice">This review was superseded. Return to the task overview for the current checkpoint.</p>}
    {message && <p role="status" className="notice success">{message}</p>}
    {error && <p role="alert" className="notice">{error}</p>}
    <div className="review-grid">
      <div className="review-body">
        {isDiff
          ? <UnifiedDiff content={cp.content_md} onComment={canComment ? selectTarget : undefined}/>
          : <Document content={cp.content_md} onComment={canComment ? selectTarget : undefined}/>}
      </div>
      <aside>
        {isDiff && <Scorecard run={run}/>}
        {(canDecide || canSubmitMerge) && <section className="panel">
          <h2>{merging ? 'Merge in progress' : 'Review decision'}</h2>
          {canSubmitMerge ? <>
            {matchingProposal && <p className="meta">Merge into <code>{proposal.target_branch}</code></p>}
            {proposalError && <div className="notice">{proposalError} <button type="button" onClick={() => retryProposal(count => count + 1)}>Check proposal again</button></div>}
            {!proposalError && !canMerge && <p className="quiet">{ticketId && !proposal ? 'Checking the verified proposal…' : 'The current proposal and verification must match this revision before merge.'}</p>}
            <button type="button" className="primary" disabled={pending || !canMerge} onClick={merge}>{merging ? 'Retry merge' : 'Approve & merge worktree'}</button>
          </> : <button type="button" className="primary" disabled={pending} onClick={() => void decide('approved')}>Approve {cp.stage}</button>}
          {canDecide && <form className="decision-form" onSubmit={event => {event.preventDefault(); void decide('changes_requested')}}>
            <label htmlFor="review-reason">Reason for requesting changes</label>
            <textarea id="review-reason" rows={3} required value={reason} onChange={event => setReason(event.target.value)}/>
            <button disabled={pending || !reason.trim()}>Request changes</button>
          </form>}
        </section>}
        <section className="panel">
          <h2>Comments</h2>
          {notes.length ? <ul className="comments">{notes.map(note => <li key={note.id}>
            <strong>{[note.file_path, note.line_or_section].filter(Boolean).join(' · ') || (note.target_type === 'changes_requested' ? 'Changes requested' : 'General comment')}</strong>
            <p>{note.comment}</p>
          </li>)}</ul> : <p className="quiet">No comments yet.</p>}
          {canComment && <form className="comment-form" onSubmit={addComment}>
            <label htmlFor="review-comment">Comment <span className="quiet">{targetLabel || '· General'}</span></label>
            {targetLabel && <button type="button" className="text-button" onClick={() => selectTarget({target_type: 'section'})}>Clear target</button>}
            <textarea ref={commentInput} id="review-comment" rows={3} required value={comment} onChange={event => setComment(event.target.value)}/>
            <button disabled={pending || !comment.trim()}>Save comment</button>
          </form>}
        </section>
      </aside>
    </div>
  </main>
}

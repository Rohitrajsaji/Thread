import {useCallback,useEffect,useRef,useState} from 'react'
import {createRoot} from 'react-dom/client'
import {api,Checkpoint,date,HttpError,label,reviewPath,Snapshot,stageText,taskPath,Thread,title} from './model'
import {Review} from './review'
import {MissionControl} from './mission'
import type {MissionAvailability, MissionView} from './mission'
import './style.css'

function Overview({data}:{data:Snapshot}){
  const {thread:t,checkpoints,tickets}=data
  const active=checkpoints.find(c=>c.status==='pending' && c.waits_for_person)
  const [state,next]=stageText[t.status]??[label(t.status),'See activity for the latest update']
  const reviews=[...checkpoints].sort((a,b)=>b.created_at.localeCompare(a.created_at))
  const reviewLink=(c:Checkpoint)=>reviewPath(t.id,c.id)
  return <main id="content"><div className="crumb">Task overview</div><h1>{t.title}</h1>
  <p className="meta">Track {t.track} <span>·</span> Repository revision <code title={t.base_sha}>{t.base_sha.slice(0,8)}</code></p>
  <section className={'attention '+(active?'waiting':'')}><div><h2>{state}</h2><p>{next}</p>{t.risk_reasons.length>0&&<details><summary>Why this review path?</summary><ul>{t.risk_reasons.map(r=><li key={r}>{label(r)}</li>)}</ul></details>}</div>{active&&<a className="primary" href={reviewLink(active)}>Review {title(active,checkpoints).toLowerCase()} →</a>}</section>
  <div className="overview"><div><section><h2>Tickets <small>{tickets.length}</small></h2>{tickets.length===0?<p className="quiet">Tickets appear when a plan is prepared.</p>:tickets.map(k=><details key={k.id} className="row"><summary>{k.title}<span>{label(k.status)}</span></summary><dl><dt>Role</dt><dd>{k.role}</dd><dt>Depends on</dt><dd>{k.depends_on.join(', ')||'No dependencies'}</dd>{k.worktree_branch&&<><dt>Branch</dt><dd><code>{k.worktree_branch}</code></dd></>}</dl></details>)}</section>
  <section><h2>Review history</h2>{reviews.map(c=><a className="row link" key={c.id} href={reviewLink(c)}><b>{title(c,checkpoints)}</b><span>{label(c.status)} · <code>{c.git_head_sha.slice(0,8)}</code></span></a>)}{!reviews.length&&<p className="quiet">No checkpoints recorded yet.</p>}</section></div>
  <aside><section><h2>Usage</h2><dl><dt>Credits used</dt><dd>{t.credits_used}</dd><dt>Turns used</dt><dd>{t.turns_used}</dd></dl></section><section><h2>Activity</h2><ol className="activity">{[...data.events].sort((a,b)=>b.id-a.id).slice(0,30).map(e=><li key={e.id}><b>{label(e.type)}</b><time>{date(e.created_at)}</time></li>)}</ol></section></aside></div></main>
}
function routeId(value: string | undefined) {
  if (!value) return undefined
  try { return decodeURIComponent(value) } catch { return value }
}

function App(){
  const [, area, taskSegment, , reviewSegment]=window.location.pathname.split('/')
  const missionView: MissionView | null = area === 'mission-control'
    ? (taskSegment === 'memory' || taskSegment === 'policy' ? taskSegment : 'knowledge') : null
  const task=area === 'tasks' ? routeId(taskSegment) : undefined,review=routeId(reviewSegment)
  const [data,setData]=useState<Snapshot|null>(null),[tasks,setTasks]=useState<Thread[]>([])
  const [connection,setConnection]=useState('Connecting'),[error,setError]=useState('')
  const [mission,setMission]=useState<MissionAvailability|null>(null)
  const latestRequest=useRef(0)
  useEffect(()=>{
    let current = true
    api<MissionAvailability>('mission-control').then(
      value => { if (current) setMission(value) },
      () => { if (current) setMission({enabled: false, graph_enabled: false}) },
    )
    return () => { current = false }
  },[])
  const refresh=useCallback(async()=>{
    const request=++latestRequest.current
    try{
      const list=await api<Thread[]>('threads')
      const id=task||list[0]?.id
      const snapshot=id?await api<Snapshot>('threads/'+encodeURIComponent(id)):null
      if(request!==latestRequest.current)return
      setTasks(list);setData(snapshot);setError('');setConnection('Connected')
    }catch(e){
      if(request!==latestRequest.current)return
      if(e instanceof HttpError && [401,403,404].includes(e.status)){setData(null);setTasks([])}
      setConnection(e instanceof HttpError&&[401,403].includes(e.status)?'Session expired':'Disconnected')
      setError(e instanceof Error?e.message:'Unable to reach the local service')
    }
  },[task])
  useEffect(()=>{
    if(missionView)return
    void refresh();const id=setInterval(refresh,5000);window.addEventListener('focus',refresh);return()=>{clearInterval(id);window.removeEventListener('focus',refresh)}
  },[missionView,refresh])
  const threadId=data?.thread.id
  const lastEvent=data?.events.at(-1)?.id ?? 0
  const eventCursor=useRef(lastEvent)
  useEffect(()=>{eventCursor.current=lastEvent},[lastEvent])
  useEffect(()=>{
    if (!threadId || connection==='Session expired') return
    const params=new URLSearchParams({thread_id:threadId,after:String(eventCursor.current)})
    const stream=new EventSource('/api/events?'+params)
    let debounce: number | undefined
    stream.onmessage=()=>{
      if(debounce===undefined)debounce=window.setTimeout(()=>{debounce=undefined;void refresh()},150)
    }
    return ()=>{stream.close();window.clearTimeout(debounce)}
  },[threadId,connection==='Session expired',refresh])
  const cp=data?.checkpoints.find(c=>c.id===review)
  return <><a className="skip" href="#content">Skip to content</a><header className="mast"><a href="/" className="brand">Thread</a><span className="mastsub">Local review</span><div className="grow"/>
  {mission?.enabled&&<a href="/mission-control" aria-current={missionView?'page':undefined}>Mission Control</a>}
  {tasks.length>1&&<label className="chooser">Task <select value={data?.thread.id??''} onChange={e=>location.assign(taskPath(e.target.value))}>{tasks.map(t=><option key={t.id} value={t.id}>{t.title}</option>)}</select></label>}{!missionView&&<span className={'connection '+(connection==='Connected'?'online':'')}>{connection}</span>}</header>
  {missionView ? <MissionControl view={missionView} availability={mission}/> : <>
  {error&&<div role="alert" className="notice">{error} <button onClick={refresh}>Reconnect</button></div>}
  {data?(review?(cp?<Review key={cp.id} data={data} cp={cp} online={connection==='Connected'} refresh={refresh}/>:<main id="content"><h1>Review unavailable</h1><a href={taskPath(data.thread.id)}>Open current task</a></main>):<Overview data={data}/>):<main id="content"><h1>{connection==='Connected'?'No active tasks':connection}</h1><p>{connection==='Connected'?'Start a task in Copilot Chat to review its progress here.':connection==='Session expired'?'Open the local link printed by thread ui.':'Waiting for the local review service.'}</p></main>}</>}</>
}
createRoot(document.getElementById('root')!).render(<App/>)

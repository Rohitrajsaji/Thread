import {useEffect, useMemo, useState} from 'react'
import type {FormEvent} from 'react'
import {api, date, label} from './model'
import './mission.css'

export type MissionView = 'knowledge' | 'memory' | 'policy'
export interface MissionAvailability {enabled: boolean; graph_enabled: boolean}

const views: Record<MissionView, string> = {
  knowledge: 'Knowledge graph',
  memory: 'Memory promotion',
  policy: 'Policy & config',
}

type Provenance = 'observed' | 'inferred'
interface GraphNode {id: string; label: string; kind: string}
interface GraphEdge {source: string; target: string; relation: string; provenance: Provenance}
interface Graph {nodes: GraphNode[]; edges: GraphEdge[]}
interface Observation {
  id: number
  thread_id: string | null
  type: string
  payload_json: string
  created_at: string
  promoted_path: string | null
}
type ConfigName = 'config' | 'policy' | 'scope'
interface ConfigDocument {
  name: ConfigName
  yaml: string
  revision: string
  effective: Record<string, unknown> | null
}
interface ConfigSaved extends ConfigDocument {staled_checkpoints: number}

function errorText(error: unknown) {
  return error instanceof Error ? error.message : 'Mission Control could not complete the request.'
}

function GraphDiagram({graph, selected}: {graph: Graph; selected: string | null}) {
  const nodes = graph.nodes.slice(0, 24)
  const points = new Map(nodes.map((node, index) => {
    const angle = (index / nodes.length) * Math.PI * 2 - Math.PI / 2
    return [node.id, {x: 420 + Math.cos(angle) * 310, y: 230 + Math.sin(angle) * 170}]
  }))
  return <svg className="graph-diagram" viewBox="0 0 840 460" role="img" aria-label="Graph preview. Observed connections are solid and inferred connections are dashed.">
    {graph.edges.map((edge, index) => {
      const source = points.get(edge.source), target = points.get(edge.target)
      if (!source || !target) return null
      const relevant = !selected || edge.source === selected || edge.target === selected
      return <line key={index} className={edge.provenance + (relevant ? '' : ' dim')} x1={source.x} y1={source.y} x2={target.x} y2={target.y}/>
    })}
    {nodes.map(node => {
      const point = points.get(node.id)!
      return <g key={node.id} className={selected === node.id ? 'selected' : undefined} transform={`translate(${point.x} ${point.y})`}>
        <title>{node.label}</title>
        <circle r="7"/>
        <text textAnchor="middle" y="-13">{node.label.length > 22 ? node.label.slice(0, 21) + '…' : node.label}</text>
      </g>
    })}
  </svg>
}

function KnowledgeGraph({enabled}: {enabled: boolean}) {
  const [query, setQuery] = useState('')
  const [provenance, setProvenance] = useState<'' | Provenance>('')
  const [filter, setFilter] = useState({query: '', provenance: '' as '' | Provenance})
  const [graph, setGraph] = useState<Graph | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    if (!enabled) return
    let current = true
    const params = new URLSearchParams({query: filter.query})
    if (filter.provenance) params.set('provenance', filter.provenance)
    setError(''); setGraph(null); setSelected(null)
    api<Graph>('mission-control/graph?' + params)
      .then(result => { if (current) setGraph(result) }, error => { if (current) setError(errorText(error)) })
    return () => { current = false }
  }, [enabled, filter])
  const byId = useMemo(() => new Map(graph?.nodes.map(node => [node.id, node])), [graph])
  if (!enabled) return <section className="panel"><h2>Context index disabled</h2><p>Enable the 3C feature in the configuration to browse its knowledge graph.</p></section>
  const displayedEdges = graph?.edges.filter(edge => !selected || [edge.source, edge.target].includes(selected)) ?? []
  return <section className="panel">
    <form className="studio-filters" onSubmit={event => {
      event.preventDefault()
      setFilter({query: query.trim(), provenance})
    }}>
      <label>Find nodes <input type="search" maxLength={250} value={query} onChange={event => setQuery(event.target.value)}/></label>
      <label>Provenance <select value={provenance} onChange={event => setProvenance(event.target.value as '' | Provenance)}>
        <option value="">All connections</option><option value="observed">Observed</option><option value="inferred">Inferred</option>
      </select></label>
      <button type="submit">Search</button>
    </form>
    {error && <p className="notice" role="alert">{error}</p>}
    {!graph && !error && <p role="status">Loading graph…</p>}
    {graph && (graph.nodes.length ? <>
      <ul className="graph-legend" aria-label="Connection provenance">
        <li className="observed">Observed</li><li className="inferred">Inferred</li>
      </ul>
      <GraphDiagram graph={graph} selected={selected}/>
      <div className="graph-details">
        <section aria-label="Nodes"><h2>Nodes</h2><div className="graph-nodes">
          {graph.nodes.map(node => <button key={node.id} type="button" aria-pressed={selected === node.id}
            onClick={() => setSelected(selected === node.id ? null : node.id)}>
            {node.label} <small>{label(node.kind)}</small>
          </button>)}
        </div></section>
        <section aria-label="Connections"><h2>Connections</h2>
          {displayedEdges.length ? <ul className="graph-edges">
            {displayedEdges.map((edge, index) => <li key={index}>
              <span className={'provenance ' + edge.provenance}>{label(edge.provenance)}</span>
              <span>{byId.get(edge.source)?.label ?? edge.source} <strong>{label(edge.relation)}</strong> {byId.get(edge.target)?.label ?? edge.target}</span>
            </li>)}
          </ul> : <p className="quiet">No connections match this view.</p>}
        </section>
      </div>
    </> : <p className="quiet">No indexed nodes match. Run the context indexer or change the filters.</p>)}
  </section>
}

function prettyPayload(payload: string) {
  try { return JSON.stringify(JSON.parse(payload), null, 2) }
  catch { return payload }
}

function MemoryStudio() {
  const [observations, setObservations] = useState<Observation[] | null>(null)
  const [selected, setSelected] = useState<number | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  useEffect(() => {
    let current = true
    api<{observations: Observation[]}>('mission-control/observations')
      .then(result => { if (current) setObservations(result.observations) }, error => { if (current) setError(errorText(error)) })
    return () => { current = false }
  }, [])
  const observation = observations?.find(item => item.id === selected)
  async function promote(event: FormEvent) {
    event.preventDefault()
    if (!observation || !confirmed || saving) return
    setSaving(true); setError(''); setMessage('')
    try {
      const result = await api<{path: string}>('mission-control/observations/' + observation.id + '/promote', {confirm: true})
      setObservations(items => items?.map(item => item.id === observation.id ? {...item, promoted_path: result.path} : item) ?? null)
      setMessage('Saved ' + result.path)
    } catch (error) { setError(errorText(error)) }
    finally { setSaving(false); setConfirmed(false) }
  }
  return <>
    {error && <p role="alert" className="notice">{error}</p>}
    {message && <p role="status" className="notice success">{message}</p>}
    <div className="memory-grid">
      <section className="panel">
        <h2>Recent observations</h2>
        {!observations && !error && <p role="status">Loading observations…</p>}
        {observations?.length === 0 && <p className="quiet">There are no observations to promote.</p>}
        <ul className="observation-list">{observations?.map(item => <li key={item.id}>
          <button type="button" disabled={saving} aria-pressed={item.id === selected}
            onClick={() => { setSelected(item.id); setConfirmed(false); setMessage(''); setError('') }}>
            <strong>{label(item.type)}</strong>
            <span>{date(item.created_at)}{item.promoted_path ? ' · Promoted' : ''}</span>
          </button>
        </li>)}</ul>
      </section>
      <section className="panel">
        <h2>Review observation</h2>
        {observation ? <>
          <p className="meta">{label(observation.type)}{observation.thread_id && <> · <code>{observation.thread_id}</code></>}</p>
          <pre className="studio-output">{prettyPayload(observation.payload_json)}</pre>
          {observation.promoted_path
            ? <p>Decision record <code>{observation.promoted_path}</code></p>
            : <form className="promote-form" onSubmit={promote}>
              <p>Promotion writes a Markdown record that you can review in Git.</p>
              <label><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)}/> I reviewed this observation and approve promotion.</label>
              <button type="submit" className="primary" disabled={!confirmed || saving}>{saving ? 'Promoting…' : 'Promote observation'}</button>
            </form>}
        </> : <p className="quiet">Select an observation to review its contents.</p>}
      </section>
    </div>
  </>
}

const configNames: Record<ConfigName, string> = {config: 'Configuration', policy: 'Policy', scope: 'Scope'}

function SettingValue({value}: {value: unknown}) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return <dl className="studio-settings">{Object.entries(value).map(([key, entry]) => <div key={key}>
      <dt>{label(key)}</dt><dd><SettingValue value={entry}/></dd>
    </div>)}</dl>
  }
  if (Array.isArray(value)) return value.length ? <ul className="studio-array">
    {value.map((entry, index) => <li key={index}><SettingValue value={entry}/></li>)}
  </ul> : <span className="quiet">None</span>
  return <code>{value === null ? 'Unset' : String(value)}</code>
}

function PolicyStudio() {
  const [name, setName] = useState<ConfigName>('config')
  const [document, setDocument] = useState<ConfigDocument | null>(null)
  const [contents, setContents] = useState('')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)
  const [attempt, retry] = useState(0)
  useEffect(() => {
    let current = true
    setLoading(true); setDocument(null); setMessage(''); setError('')
    api<ConfigDocument>('mission-control/config/' + name)
      .then(result => {
        if (current) { setDocument(result); setContents(result.yaml); setLoading(false) }
      }, error => {
        if (current) { setError(errorText(error)); setLoading(false) }
      })
    return () => { current = false }
  }, [name, attempt])

  const changed = document !== null && contents !== document.yaml
  function select(target: ConfigName) {
    if (target !== name && (!changed || window.confirm('Discard unsaved changes?'))) setName(target)
  }
  async function save(event: FormEvent) {
    event.preventDefault()
    if (!document || !changed || loading) return
    setLoading(true); setError(''); setMessage('')
    try {
      const result = await api<ConfigSaved>('mission-control/config/' + name, {yaml: contents, expected_revision: document.revision})
      setDocument(result); setContents(result.yaml)
      setMessage(result.staled_checkpoints === 0
        ? 'Configuration saved.'
        : `Configuration saved. Marked ${result.staled_checkpoints} ${result.staled_checkpoints === 1 ? 'approval' : 'approvals'} stale.`)
    } catch (error) { setError(errorText(error)) }
    finally { setLoading(false) }
  }
  return <>
    <nav className="studio-tabs" aria-label="Configuration files">
      {(Object.keys(configNames) as ConfigName[]).map(item => <button key={item} type="button" aria-pressed={item === name}
        disabled={loading} onClick={() => select(item)}>{configNames[item]}</button>)}
    </nav>
    {error && <p role="alert" className="notice">{error}</p>}
    {message && <p role="status" className="notice success">{message}</p>}
    {loading && !document && <p role="status">Loading configuration…</p>}
    {!document && !loading && error && <button type="button" onClick={() => retry(count => count + 1)}>Retry</button>}
    {document && <div className="policy-grid">
      <form className="panel" onSubmit={save}>
        <label htmlFor="studio-yaml">.thread/{name}.yaml</label>
        <p className="meta">Governing changes can invalidate approvals for active threads.</p>
        <textarea id="studio-yaml" className="studio-yaml" spellCheck={false} disabled={loading}
          maxLength={65536} rows={18} value={contents} onChange={event => setContents(event.target.value)}/>
        <div className="studio-actions">
          <button type="submit" className="primary" disabled={loading || !changed}>{loading ? 'Saving…' : 'Save YAML'}</button>
          <button type="button" disabled={loading} onClick={() => {
            if (!changed || window.confirm('Discard unsaved changes and reload this file?')) retry(count => count + 1)
          }}>Reload file</button>
        </div>
      </form>
      <section className="panel">
        <h2>Effective settings</h2>
        <p className="meta">Saved revision <code>{document.revision.slice(0, 10)}</code></p>
        {document.effective ? <SettingValue value={document.effective}/> : <p className="quiet">Repair the YAML to view effective settings.</p>}
      </section>
    </div>}
  </>
}

export function MissionControl({view, availability}: {view: MissionView; availability: MissionAvailability | null}) {
  return <main id="content" className="mission">
    <nav className="crumb" aria-label="Breadcrumb"><a href="/">Task reviews</a> / Mission Control</nav>
    <h1>{views[view]}</h1>
    <nav className="studio-tabs" aria-label="Mission Control">
      {(Object.keys(views) as MissionView[]).map(item => <a key={item} aria-current={item === view ? 'page' : undefined}
        href={'/mission-control/' + item}>{views[item]}</a>)}
    </nav>
    {!availability ? <p role="status">Loading Mission Control…</p>
      : !availability.enabled ? <p className="quiet">Mission Control is disabled for this repository.</p>
      : view === 'knowledge' ? <KnowledgeGraph enabled={availability.graph_enabled}/>
      : view === 'memory' ? <MemoryStudio/> : <PolicyStudio/>}
  </main>
}

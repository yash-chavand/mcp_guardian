import React, { useEffect, useRef, useState, useCallback } from 'react'
import StatCards from './components/StatCards.jsx'
import AlertAnnouncer from './components/AlertAnnouncer.jsx'
import Filters from './components/Filters.jsx'
import LiveTable from './components/LiveTable.jsx'
import ScoreChart from './components/ScoreChart.jsx'
import LimitationsPanel from './components/LimitationsPanel.jsx'
import AgentChat from './components/AgentChat.jsx'
import RiskBreakdown from './components/RiskBreakdown.jsx'
import AttackGraphView from './components/AttackGraphView.jsx'
import DriftMonitor from './components/DriftMonitor.jsx'
import ExplainableAlerts from './components/ExplainableAlerts.jsx'
import { fetchStatus, fetchRecent } from './api.js'

const POLL_MS = 2000

export default function App() {
  const [status, setStatus] = useState(null)
  const [recent, setRecent] = useState([])
  const [connState, setConnState] = useState('connecting') // connecting | live | error
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [announce, setAnnounce] = useState('')
  const [activeTab, setActiveTab] = useState('chat') // chat | dashboard | graph | drift
  const [selectedSessionId, setSelectedSessionId] = useState('default')
  const prevBlockedCount = useRef(0)
  const failCount = useRef(0)

  const poll = useCallback(async () => {
    try {
      const [s, r] = await Promise.all([fetchStatus(), fetchRecent(50)])
      setStatus(s)
      setRecent(r)
      setConnState('live')
      failCount.current = 0

      if (s.blocked > prevBlockedCount.current) {
        const newCount = s.blocked - prevBlockedCount.current
        setAnnounce(`${newCount} new request${newCount > 1 ? 's' : ''} blocked. Total blocked: ${s.blocked}.`)
      }
      prevBlockedCount.current = s.blocked
    } catch (e) {
      failCount.current += 1
      if (failCount.current >= 2) setConnState('error')
    }
  }, [])

  useEffect(() => {
    poll()
    const id = setInterval(poll, POLL_MS)
    return () => clearInterval(id)
  }, [poll])

  const filteredRows = recent.filter(d => {
    const decision = d.decision || (d.blocked ? 'BLOCK' : 'ALLOW');
    if (filter === 'blocked' && decision !== 'BLOCK') return false
    if (filter === 'allowed' && decision !== 'ALLOW') return false
    if (filter === 'monitored' && decision !== 'MONITOR') return false
    if (search) {
      const q = search.toLowerCase()
      if (!d.session_id?.toLowerCase().includes(q) && !d.tool?.toLowerCase().includes(q)) return false
    }
    return true
  })

  // Extract distinct sessions from recent rows for graph dropdown
  const distinctSessions = Array.from(new Set(recent.map(r => r.session_id).filter(Boolean)))

  return (
    <>
      <a href="#main-content" className="skip-link">Skip to main content</a>
      <AlertAnnouncer message={announce} />

      <header className="app-header">
        <div className="brand">
          <span className={`live-dot live-dot-${connState}`} aria-hidden="true" />
          <h1>MCP Guardian V2 — Enterprise Adaptive Security Gateway</h1>
        </div>
        <p className="app-sub">
          Multi-layer defense-in-depth for Model Context Protocol traffic: Expected vs Actual Semantics · GRU Sequence Anomaly · ADWIN Drift Detection · Entity Graph · Attack Graph Correlation.
        </p>
        {connState === 'error' && (
          <div className="conn-error" role="alert">
            Unable to reach the Guardian proxy. Retrying… check that the proxy server is running.
          </div>
        )}
      </header>

      <nav className="tab-navigation">
        <button
          className={`tab-btn ${activeTab === 'chat' ? 'active' : ''}`}
          onClick={() => setActiveTab('chat')}
        >
          🤖 AI Agent Sandbox
        </button>
        <button
          className={`tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setActiveTab('dashboard')}
        >
          🛡️ Live Monitor
        </button>
        <button
          className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`}
          onClick={() => setActiveTab('graph')}
        >
          🕸️ Attack Graph
        </button>
        <button
          className={`tab-btn ${activeTab === 'drift' ? 'active' : ''}`}
          onClick={() => setActiveTab('drift')}
        >
          📈 Concept Drift
        </button>
      </nav>

      <main id="main-content">
        {activeTab === 'chat' && (
          <AgentChat onMessageSent={poll} />
        )}

        {activeTab === 'dashboard' && (
          <>
            <StatCards status={status} connState={connState} />

            <div className="dashboard-grid-v2">
              <div className="chart-wrapper">
                <ScoreChart rows={recent} />
              </div>
              <RiskBreakdown recentEvents={recent} />
            </div>

            <ExplainableAlerts recentEvents={recent} />

            <section aria-labelledby="table-heading" style={{ marginTop: '28px' }}>
              <div className="table-header-row">
                <h2 id="table-heading">Audit Log & Decisions (3-Tier)</h2>
                <Filters filter={filter} onFilterChange={setFilter} search={search} onSearchChange={setSearch} />
              </div>
              <LiveTable rows={filteredRows} />
            </section>
          </>
        )}

        {activeTab === 'graph' && (
          <div className="graph-tab-wrapper">
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <label htmlFor="session-select" style={{ fontSize: '0.85rem', color: 'var(--muted)', fontWeight: 600 }}>
                Select Session:
              </label>
              <select
                id="session-select"
                value={selectedSessionId}
                onChange={(e) => setSelectedSessionId(e.target.value)}
                style={{
                  background: 'var(--panel2)',
                  border: '1px solid var(--border)',
                  color: 'var(--text)',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontFamily: 'var(--mono)'
                }}
              >
                <option value="default">default</option>
                {distinctSessions.filter(s => s !== 'default').map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <AttackGraphView sessionId={selectedSessionId} />
          </div>
        )}

        {activeTab === 'drift' && (
          <div className="drift-tab-wrapper">
            <DriftMonitor />
          </div>
        )}

        <LimitationsPanel />
      </main>

      <footer className="app-footer">
        MCP Guardian V2 &nbsp;·&nbsp; Adaptive Model Context Protocol Security &nbsp;·&nbsp; Real-time Multi-Score Defense
      </footer>
    </>
  )
}

import React from 'react'

export default function StatCards({ status, connState }) {
  const total = status?.total_requests ?? 0
  const allowed = status?.allowed ?? (total - (status?.blocked || 0) - (status?.monitored || 0))
  const monitored = status?.monitored ?? 0
  const blocked = status?.blocked ?? 0
  const rate = status ? Math.round((status.block_rate || 0) * 100) : 0
  const latency = status?.average_latency_ms ?? 1.8

  return (
    <section aria-labelledby="stats-heading" className="stats-section">
      <h2 id="stats-heading" className="visually-hidden">Live traffic statistics</h2>
      <div className="stats-row">
        <div className="stat-card" role="group" aria-label={`Total requests: ${total}`}>
          <div className="stat-value">{total}</div>
          <div className="stat-label">Total Requests</div>
        </div>
        <div className="stat-card stat-success" role="group" aria-label={`Allowed: ${allowed}`}>
          <div className="stat-value">{Math.max(0, allowed)}</div>
          <div className="stat-label">Allowed</div>
        </div>
        <div className="stat-card stat-warning" role="group" aria-label={`Monitored: ${monitored}`}>
          <div className="stat-value">{monitored}</div>
          <div className="stat-label">Monitored</div>
        </div>
        <div className="stat-card stat-danger" role="group" aria-label={`Blocked: ${blocked}`}>
          <div className="stat-value">{blocked}</div>
          <div className="stat-label">Blocked</div>
        </div>
        <div className="stat-card" role="group" aria-label={`Block rate: ${rate} percent`}>
          <div className="stat-value">{rate}%</div>
          <div className="stat-label">Block Rate</div>
        </div>
        <div className="stat-card stat-latency" role="group" aria-label={`Latency: ${latency} ms`}>
          <div className="stat-value">{latency} <span className="unit-label">ms</span></div>
          <div className="stat-label">Fast Path Latency</div>
        </div>
        <div
          className={`stat-card stat-conn stat-conn-${connState}`}
          role="status"
          aria-label={`Connection to Guardian proxy: ${connState}`}
        >
          <div className="stat-value stat-conn-icon">
            {connState === 'live' ? '●' : connState === 'connecting' ? '○' : '✕'}
          </div>
          <div className="stat-label">
            {connState === 'live' ? 'Live V2' : connState === 'connecting' ? 'Connecting…' : 'Disconnected'}
          </div>
        </div>
      </div>
    </section>
  )
}

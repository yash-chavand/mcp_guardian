import React from 'react'

export default function LiveTable({ rows }) {
  const getDecisionBadge = (decision, blocked) => {
    const dec = decision || (blocked ? 'BLOCK' : 'ALLOW');
    if (dec === 'BLOCK') return <span className="badge badge-danger">BLOCK</span>;
    if (dec === 'MONITOR') return <span className="badge badge-warning">MONITOR</span>;
    return <span className="badge badge-success">ALLOW</span>;
  };

  const getRiskBadge = (level) => {
    switch (level) {
      case 'critical': return <span className="badge badge-critical">critical</span>;
      case 'high': return <span className="badge badge-danger">high</span>;
      case 'medium': return <span className="badge badge-warning">medium</span>;
      default: return <span className="badge badge-info">low</span>;
    }
  };

  return (
    <div className="table-wrap" role="region" aria-label="Recent request decisions" tabIndex={0}>
      <table>
        <caption className="visually-hidden">
          Recent MCP tool call decisions, newest first. {rows.length} rows shown.
        </caption>
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Decision</th>
            <th scope="col">Risk Level</th>
            <th scope="col">Tool</th>
            <th scope="col">Risk Score</th>
            <th scope="col">Latency</th>
            <th scope="col">Primary Reason</th>
            <th scope="col">Correlation ID</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr><td colSpan={8} className="empty-cell">No matching traffic yet.</td></tr>
          )}
          {rows.map((d, i) => (
            <tr key={`${d.session_id}-${d.timestamp}-${i}`} className={d.decision === 'BLOCK' || d.blocked ? 'row-blocked' : d.decision === 'MONITOR' ? 'row-monitored' : ''}>
              <td>{new Date(d.timestamp * 1000).toLocaleTimeString()}</td>
              <td>{getDecisionBadge(d.decision, d.blocked)}</td>
              <td>{getRiskBadge(d.risk_level)}</td>
              <td className="tool-cell"><code>{d.tool}</code></td>
              <td><code className="score-num">{(d.risk_score || d.anomaly_score || 0).toFixed(3)}</code></td>
              <td><span className="latency-tag">{d.latency_ms ? `${d.latency_ms}ms` : '< 2ms'}</span></td>
              <td className="reason-cell">{d.reason || 'normal'}</td>
              <td><code className="corr-cell">{(d.correlation_id || d.event_id || 'N/A').slice(0, 8)}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

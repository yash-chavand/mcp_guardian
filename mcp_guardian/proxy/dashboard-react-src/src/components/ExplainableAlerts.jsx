import React from 'react';

export default function ExplainableAlerts({ recentEvents }) {
  // Extract blocked and monitored events with explainable reasons
  const flaggedEvents = (recentEvents || []).filter(e => e.decision === 'BLOCK' || e.decision === 'MONITOR');

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-danger';
      case 'medium': return 'badge-warning';
      default: return 'badge-info';
    }
  };

  return (
    <div className="card explainable-alerts-card">
      <div className="card-header">
        <h3>🔍 Explainable Security Diagnostic Panel</h3>
        <span className="badge badge-danger">{flaggedEvents.length} Active Diagnostics</span>
      </div>

      {flaggedEvents.length === 0 ? (
        <div className="empty-alerts-box">
          <span>🛡️ No anomalous requests flagged in recent traffic. All systems nominal.</span>
        </div>
      ) : (
        <div className="alerts-accordion">
          {flaggedEvents.slice(0, 4).map((ev, idx) => (
            <div key={ev.event_id || idx} className={`alert-diag-card alert-border-${ev.risk_level}`}>
              <div className="alert-diag-header">
                <div className="alert-title-wrap">
                  <span className={`badge ${ev.decision === 'BLOCK' ? 'badge-danger' : 'badge-warning'}`}>
                    {ev.decision}
                  </span>
                  <span className="tool-tag">{ev.tool || ev.tool_name}</span>
                  <span className="corr-id">ID: {(ev.correlation_id || 'N/A').slice(0, 8)}</span>
                </div>
                <div className="score-wrap">
                  <span className="risk-score-label">Risk Score:</span>
                  <span className="risk-score-val">{(ev.risk_score || ev.anomaly_score || 0).toFixed(3)}</span>
                </div>
              </div>

              <div className="reasons-container">
                <h4>Root Cause Breakdown:</h4>
                <div className="reasons-list">
                  {(ev.reasons || []).map((r, rIdx) => (
                    <div key={rIdx} className="reason-item">
                      <span className={`badge ${getSeverityBadge(r.severity)}`}>{r.severity}</span>
                      <span className="reason-type-tag">[{r.type}]</span>
                      <span className="reason-msg-text">{r.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

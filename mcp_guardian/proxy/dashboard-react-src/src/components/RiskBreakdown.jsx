import React from 'react';

export default function RiskBreakdown({ recentEvents }) {
  // Aggregate detection source frequency from recent events
  const counts = {
    rules: 0,
    isolation_forest: 0,
    sequence: 0,
    semantic: 0,
    drift: 0,
    entity: 0,
    destination: 0,
    injection: 0
  };

  if (recentEvents && recentEvents.length > 0) {
    recentEvents.forEach(e => {
      const sub = e.sub_scores || {};
      if ((sub.rules || 0) > 0.5) counts.rules += 1;
      if ((sub.isolation_forest || 0) > 0.5) counts.isolation_forest += 1;
      if ((sub.sequence || 0) > 0.5) counts.sequence += 1;
      if ((sub.semantic || 0) > 0.5) counts.semantic += 1;
      if ((sub.drift || 0) > 0.5) counts.drift += 1;
      if ((sub.entity || 0) > 0.5) counts.entity += 1;
      if ((sub.destination || 0) > 0.5) counts.destination += 1;
      if ((sub.injection || 0) > 0.5) counts.injection += 1;
    });
  }

  const maxVal = Math.max(1, ...Object.values(counts));

  const items = [
    { label: "Deterministic Hard Rules", key: "rules", color: "#f87171" },
    { label: "Isolation Forest ML", key: "isolation_forest", color: "#60a5fa" },
    { label: "GRU Sequence Anomaly", key: "sequence", color: "#c084fc" },
    { label: "Semantic Expected vs Actual", key: "semantic", color: "#fbbf24" },
    { label: "Behavioral Concept Drift", key: "drift", color: "#34d399" },
    { label: "Entity Relationship Alignment", key: "entity", color: "#f43f5e" },
    { label: "Destination Novelty Tracker", key: "destination", color: "#38bdf8" },
    { label: "Multi-Layer Prompt Injection", key: "injection", color: "#e11d48" }
  ];

  return (
    <div className="card risk-breakdown-card">
      <div className="card-header">
        <h3>🛡️ Multi-Layer Detection Source Breakdown</h3>
        <span className="badge badge-info">Real-time Signals</span>
      </div>
      <div className="breakdown-grid">
        {items.map(item => {
          const val = counts[item.key] || 0;
          const pct = Math.round((val / maxVal) * 100);
          return (
            <div key={item.key} className="breakdown-item">
              <div className="breakdown-label">
                <span>{item.label}</span>
                <span className="count-tag">{val} hits</span>
              </div>
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${Math.max(4, pct)}%`, backgroundColor: item.color }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

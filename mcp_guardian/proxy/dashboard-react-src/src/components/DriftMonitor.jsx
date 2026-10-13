import React, { useState, useEffect } from 'react';
import { fetchDriftStatus } from '../api';

export default function DriftMonitor() {
  const [driftData, setDriftData] = useState(null);

  useEffect(() => {
    let mounted = true;
    async function loadDrift() {
      try {
        const data = await fetchDriftStatus();
        if (mounted) setDriftData(data);
      } catch (err) {
        console.error('Drift fetch error:', err);
      }
    }
    loadDrift();
    const interval = setInterval(loadDrift, 4000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const baselines = driftData?.baselines || {};
  const candidates = driftData?.candidates || {};
  const recentDrifts = driftData?.recent_drifts || [];

  return (
    <div className="card drift-monitor-card">
      <div className="card-header">
        <h3>📈 Behavioral Concept Drift Monitor (ADWIN)</h3>
        <span className="badge badge-teal">Adaptive Baselines</span>
      </div>

      <div className="drift-grid">
        <div className="drift-metrics-panel">
          <h4>Active Rolling Baselines</h4>
          <div className="metric-tiles">
            {Object.keys(baselines).map(k => {
              const b = baselines[k];
              return (
                <div key={k} className="metric-tile">
                  <span className="metric-name">{b.name}</span>
                  <div className="metric-values">
                    <span className="metric-mean">μ = {b.mean.toFixed(2)}</span>
                    <span className="metric-std">σ = {b.std.toFixed(2)}</span>
                  </div>
                  <span className="metric-count">{b.count} observations</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="drift-status-panel">
          <h4>Candidate Baseline Stages & Drift Log</h4>
          {Object.keys(candidates).length === 0 && recentDrifts.length === 0 ? (
            <div className="no-drift-box">
              <span className="check-icon">✅</span>
              <span>Distribution is stationary. No unapproved malicious drift staged.</span>
            </div>
          ) : (
            <div className="drift-alert-list">
              {recentDrifts.slice(-3).map((d, i) => (
                <div key={i} className="drift-alert-item">
                  <div className="alert-top">
                    <span className="badge badge-warning">{d.metric_name}</span>
                    <span className="z-tag">z-score: {d.z_score}σ</span>
                  </div>
                  <p className="alert-desc">
                    Concept drift detected. Staged to validation window ({d.status}).
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import { fetchAttackGraph } from '../api';

export default function AttackGraphView({ sessionId, activeSessionId = 'default' }) {
  const currentSession = sessionId || activeSessionId;
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let mounted = true;
    async function loadGraph() {
      try {
        setLoading(true);
        const data = await fetchAttackGraph(currentSession);
        if (mounted) setGraph(data);
      } catch (err) {
        console.error('Graph fetch error:', err);
      } finally {
        if (mounted) setLoading(false);
      }
    }
    loadGraph();
    const interval = setInterval(loadGraph, 4000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [currentSession]);

  const getNodeBadgeClass = (type) => {
    switch (type) {
      case 'session': return 'badge-session';
      case 'tool': return 'badge-tool';
      case 'resource': return 'badge-resource';
      case 'destination': return 'badge-dest';
      case 'transform': return 'badge-transform';
      default: return 'badge-default';
    }
  };

  // Mirrors the backend's ordered-subsequence check in
  // GraphRiskAnalyzer._has_ordered_chain: true if the edges contain
  // READ -> TRANSFORMED -> SENT_TO in that relative order (other edges may
  // fall in between). This is the classic "read sensitive data -> encode ->
  // external request" exfiltration chain.
  const hasOrderedChain = (edges, relations) => {
    let cursor = 0;
    for (const e of edges) {
      if (cursor >= relations.length) break;
      if (e.relation === relations[cursor]) cursor += 1;
    }
    return cursor === relations.length;
  };
  const hasEncodeExfiltrationChain = hasOrderedChain(graph.edges, ['READ', 'TRANSFORMED', 'SENT_TO']);

  return (
    <div className="card attack-graph-card">
      <div className="card-header">
        <h3>🕸️ Session Attack Graph Correlation</h3>
        <span className="badge badge-purple">Session: {currentSession.slice(0, 15)}</span>
      </div>
      <p className="graph-subtitle">
        Visualizes session topology, tool chains, sensitive database reads, and outbound transmissions.
      </p>

      {hasEncodeExfiltrationChain && (
        <div className="chain-alert-banner" role="alert">
          <span className="chain-alert-icon">⚠️</span>
          <span className="chain-alert-text">
            <strong>Encode-Exfiltration Chain Detected</strong> — sensitive data was read,
            then encoded/transformed, then transmitted to an external destination.
          </span>
          <span className="badge badge-danger">read → encode → send</span>
        </div>
      )}

      {graph.nodes.length === 0 ? (
        <div className="empty-graph-state">
          <span>⚡ No interaction topology recorded yet for this session. Trigger tool calls in the Sandbox.</span>
        </div>
      ) : (
        <div className="graph-container">
          <div className="graph-nodes-list">
            <h4>Graph Entities ({graph.nodes.length})</h4>
            <div className="nodes-flex">
              {graph.nodes.map(n => (
                <div key={n.id} className={`graph-node-chip ${getNodeBadgeClass(n.node_type)}`}>
                  <span className="node-type-label">{n.node_type === 'transform' ? '🔐 transform' : n.node_type}</span>
                  <span className="node-title">{n.label}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="graph-edges-list">
            <h4>Data Flow & Execution Edges ({graph.edges.length})</h4>
            <div className="edges-timeline">
              {graph.edges.map(e => {
                const isTransformed = e.relation === 'TRANSFORMED';
                return (
                  <div
                    key={e.id}
                    className={`edge-row ${e.risk_level === 'high' ? 'edge-high-risk' : ''} ${isTransformed ? 'edge-transformed' : ''}`}
                  >
                    <span className="edge-src">{e.source.split(':')[1] || e.source}</span>
                    <span className={`edge-arrow ${isTransformed ? 'edge-arrow-transformed' : ''}`}>
                      ──[{isTransformed ? '🔐 ' : ''}{e.relation}]──▶
                    </span>
                    <span className="edge-tgt">{e.target.split(':')[1] || e.target}</span>
                    {e.risk_level === 'high' && <span className="badge badge-danger">High Risk Path</span>}
                    {isTransformed && <span className="badge badge-transform-tag">Encode/Transform Hop</span>}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

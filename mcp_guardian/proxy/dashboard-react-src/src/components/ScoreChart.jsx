import React from 'react'
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ReferenceLine } from 'recharts'

export default function ScoreChart({ rows }) {
  // rows are newest-first; chart wants chronological order
  const chronological = [...rows].reverse().map((d, i) => {
    const composite = d.composite_score !== undefined ? d.composite_score : (d.risk_score !== undefined ? d.risk_score : d.anomaly_score);
    return {
      idx: i,
      compositeScore: typeof composite === 'number' ? Number(composite.toFixed(3)) : 0,
      anomalyScore: typeof d.anomaly_score === 'number' ? Number(d.anomaly_score.toFixed(3)) : 0,
      decision: d.decision || (d.blocked ? 'BLOCK' : 'ALLOW'),
      tool: d.tool,
      time: new Date(d.timestamp * 1000).toLocaleTimeString(),
    }
  });

  return (
    <div className="chart-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <h3 id="chart-heading" style={{ margin: 0 }}>Composite Risk Score Over Time</h3>
        <div style={{ display: 'flex', gap: '16px', fontSize: '0.76rem', color: 'var(--muted)' }}>
          <span><strong style={{ color: '#4FD1C5' }}>―</strong> Risk Score</span>
          <span><strong style={{ color: '#F5A623' }}>---</strong> Monitor (0.45)</span>
          <span><strong style={{ color: '#FF7A7A' }}>---</strong> Block (0.70)</span>
        </div>
      </div>
      <div
        role="img"
        aria-labelledby="chart-heading"
        aria-describedby="chart-desc"
      >
        <ResponsiveContainer width="100%" height={230}>
          <LineChart data={chronological} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#223049" />
            <XAxis dataKey="idx" stroke="#8CA0C4" tick={false} label={{ value: 'Requests timeline →', position: 'insideBottom', offset: -2, fill: '#8CA0C4', fontSize: 11 }} />
            <YAxis stroke="#8CA0C4" tick={{ fontSize: 11 }} domain={[0, 1]} width={40} />
            <ReferenceLine y={0.45} stroke="#F5A623" strokeDasharray="4 4" label={{ value: 'Monitor (0.45)', fill: '#F5A623', fontSize: 10, position: 'insideTopRight' }} />
            <ReferenceLine y={0.70} stroke="#FF7A7A" strokeDasharray="4 4" label={{ value: 'Block (0.70)', fill: '#FF7A7A', fontSize: 10, position: 'insideTopRight' }} />
            <Tooltip
              contentStyle={{ background: '#121B2E', border: '1px solid #223049', borderRadius: '8px', fontSize: 12 }}
              labelFormatter={(label, payload) => payload?.[0]?.payload?.tool ? `Tool: ${payload[0].payload.tool} (${payload[0].payload.time})` : ''}
              formatter={(value, name, props) => [
                `Risk: ${value}`,
                `Decision: ${props.payload.decision}`
              ]}
            />
            <Line
              type="monotone"
              dataKey="compositeScore"
              stroke="#4FD1C5"
              strokeWidth={2}
              dot={(props) => {
                const { cx, cy, payload } = props;
                if (!cx || !cy) return null;
                const fill = payload.decision === 'BLOCK' ? '#FF7A7A' : (payload.decision === 'MONITOR' ? '#F5A623' : '#4FD1C5');
                return <circle cx={cx} cy={cy} r={payload.decision === 'BLOCK' ? 5 : 3} fill={fill} stroke="#121B2E" strokeWidth={1} key={`dot-${cx}-${cy}`} />;
              }}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <p id="chart-desc" className="visually-hidden">
        Line chart showing composite risk scores across requests. Green for ALLOW, Yellow for MONITOR, Red for BLOCK.
      </p>
    </div>
  )
}

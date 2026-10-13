import React, { useState } from 'react'

const LIMITATIONS = [
  {
    title: 'Cold-start actions may be over-flagged',
    detail: 'A tool call that is the first action in a session (e.g. an email sent with no prior lookup) can be flagged, because that pattern rarely appeared in training data. Consider allow-listing specific standalone tools if this causes false positives in your deployment.',
  },
  {
    title: 'Trained on simulated + limited real traffic',
    detail: 'The shipped model was trained on simulated session data plus a small set of real LLM-driven test runs. For production use, retrain on your own normal traffic sample (see train_realtime_model.py) before enforcing blocks.',
  },
  {
    title: 'Generic risk profiles need per-tool tuning',
    detail: 'Tools not listed in your config.json are scored with default assumptions (1 record, not outbound). Add a risk profile entry for every sensitive tool for accurate detection.',
  },
  {
    title: 'Single-process in-memory session state',
    detail: 'Session history is kept in the proxy process memory. If you run multiple proxy replicas behind a load balancer, sessions must be sticky-routed to the same replica, or session state should be moved to a shared store (e.g. Redis) — not yet implemented.',
  },
  {
    title: 'Precision improves with contamination tuning, still not perfect',
    detail: 'After calibration fixes, the detector reaches ~92% recall (catches most attacks) with ~83% precision (moderate false-alarm rate) on held-out test data. Retrain on your own normal traffic sample for best results in production.',
  },
]

export default function LimitationsPanel() {
  const [open, setOpen] = useState(false)
  return (
    <section className="limitations-panel" aria-labelledby="limitations-heading">
      <button
        type="button"
        className="limitations-toggle"
        aria-expanded={open}
        aria-controls="limitations-body"
        onClick={() => setOpen(o => !o)}
      >
        <span id="limitations-heading">⚠ Known Limitations ({LIMITATIONS.length})</span>
        <span className="chevron" aria-hidden="true">{open ? '−' : '+'}</span>
      </button>
      {open && (
        <div id="limitations-body" className="limitations-body">
          <ul>
            {LIMITATIONS.map(l => (
              <li key={l.title}>
                <strong>{l.title}.</strong> {l.detail}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}

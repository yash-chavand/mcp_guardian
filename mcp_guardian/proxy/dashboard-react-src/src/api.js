const BASE = ''; // same-origin

export async function fetchStatus() {
  const res = await fetch(`${BASE}/guardian/status`);
  if (!res.ok) throw new Error(`status ${res.status}`);
  return res.json();
}

export async function fetchRecent(limit = 50) {
  const res = await fetch(`${BASE}/guardian/recent?limit=${limit}`);
  if (!res.ok) throw new Error(`status ${res.status}`);
  return res.json();
}

export async function sendAgentChat(message, sessionId = 'default') {
  const res = await fetch(`${BASE}/agent/chat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ message, session_id: sessionId }),
  });
  if (!res.ok) throw new Error(`chat failed: ${res.status}`);
  return res.json();
}

export async function fetchSecurityEvents(limit = 50) {
  const res = await fetch(`${BASE}/security/events?limit=${limit}`);
  if (!res.ok) throw new Error(`events ${res.status}`);
  return res.json();
}

export async function fetchAttackGraph(sessionId = 'default') {
  const res = await fetch(`${BASE}/security/attack-graph/${sessionId}`);
  if (!res.ok) throw new Error(`graph ${res.status}`);
  return res.json();
}

export async function fetchDriftStatus() {
  const res = await fetch(`${BASE}/security/drift`);
  if (!res.ok) throw new Error(`drift ${res.status}`);
  return res.json();
}

export async function fetchToolsInventory() {
  const res = await fetch(`${BASE}/security/tools`);
  if (!res.ok) throw new Error(`tools ${res.status}`);
  return res.json();
}

export async function fetchRiskConfig() {
  const res = await fetch(`${BASE}/security/risk`);
  if (!res.ok) throw new Error(`risk ${res.status}`);
  return res.json();
}

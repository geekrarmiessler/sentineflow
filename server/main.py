from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from .models import AgentMetrics
from .analyzer import analyze_and_update
from .storage import get_all_nodes

app = FastAPI()


@app.get("/")
def root():
    return {"status": "ok", "message": "SentinelFlow server with risk engine running"}


@app.post("/ingest")
def ingest(metrics: AgentMetrics):
    node = analyze_and_update(metrics)
    return {
        "status": "received",
        "agent_id": node.agent_id,
        "risk_score": node.risk_score,
        "last_alert": node.last_alert,
    }


@app.get("/nodes")
def list_nodes():
    return get_all_nodes()


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>SentinelFlow Dashboard</title>
      <style>
        body { font-family: system-ui, sans-serif; margin: 20px; background: #0b1120; color: #e5e7eb; }
        h1 { margin-bottom: 0.2rem; }
        .subtitle { color: #9ca3af; margin-bottom: 1rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { padding: 8px 10px; border-bottom: 1px solid #1f2937; }
        th { text-align: left; background-color: #111827; }
        .risk-low { color: #22c55e; }
        .risk-med { color: #eab308; }
        .risk-high { color: #ef4444; font-weight: bold; }
      </style>
    </head>
    <body>
      <h1>SentinelFlow</h1>
      <div class="subtitle">Behavior-based network node risk monitor</div>

      <table>
        <thead>
          <tr>
            <th>Agent ID</th>
            <th>Hostname</th>
            <th>Last Seen</th>
            <th>Risk Score</th>
            <th>Last Alert</th>
          </tr>
        </thead>
        <tbody id="nodes-body">
          <tr><td colspan="5">Loading...</td></tr>
        </tbody>
      </table>

      <script>
        async function refreshNodes() {
          try {
            const res = await fetch('/nodes');
            const nodes = await res.json();
            const tbody = document.getElementById('nodes-body');
            tbody.innerHTML = '';

            if (!Array.isArray(nodes) || nodes.length === 0) {
              const tr = document.createElement('tr');
              tr.innerHTML = '<td colspan="5">No agents reporting yet.</td>';
              tbody.appendChild(tr);
              return;
            }

            nodes.forEach(n => {
              const tr = document.createElement('tr');

              let riskClass = 'risk-low';
              if (n.risk_score >= 70) riskClass = 'risk-high';
              else if (n.risk_score >= 30) riskClass = 'risk-med';

              tr.innerHTML = `
                <td>${n.agent_id}</td>
                <td>${n.hostname}</td>
                <td>${n.last_seen}</td>
                <td class="${riskClass}">${n.risk_score.toFixed(1)}</td>
                <td>${n.last_alert || ''}</td>
              `;
              tbody.appendChild(tr);
            });
          } catch (err) {
            console.error('Failed to load nodes:', err);
          }
        }

        setInterval(refreshNodes, 2000);
        refreshNodes();
      </script>
    </body>
    </html>
    """
    return html

from datetime import datetime, timedelta, timezone

from .models import AgentMetrics, NodeState, NODE_STATES

# how far back we look when computing "baseline" traffic
WINDOW = timedelta(minutes=2)
SPIKE_MULTIPLIER = 5.0
MIN_BASELINE_BYTES = 10_000
MAX_RISK = 100.0

# new constants for attack detection
SYN_FLOOD_THRESHOLD = 500           # per interval
PORT_SCAN_PORT_THRESHOLD = 50       # distinct ports per interval


def _window_history(node: NodeState):
    """Keep only recent metrics for this node."""
    cutoff = datetime.now(timezone.utc) - WINDOW
    return [m for m in node.history if m.timestamp >= cutoff]


def _compute_baseline_bytes_per_sec(history):
    """Average bytes/sec over the window."""
    if len(history) < 2:
        return 0.0

    deltas = []
    for prev, curr in zip(history, history[1:]):
        dt = (curr.timestamp - prev.timestamp).total_seconds()
        if dt <= 0:
            continue
        prev_bytes = prev.bytes_sent + prev.bytes_recv
        curr_bytes = curr.bytes_sent + curr.bytes_recv
        deltas.append((curr_bytes - prev_bytes) / dt)

    if not deltas:
        return 0.0

    return sum(deltas) / len(deltas)


def analyze_and_update(metrics: AgentMetrics) -> NodeState:
    """Update node metrics, recompute risk, return node state."""
    now = datetime.now(timezone.utc)
    node = NODE_STATES.get(metrics.agent_id)

    if node is None:
        # first time we've seen this agent
        node = NodeState(
            agent_id=metrics.agent_id,
            hostname=metrics.hostname,
            last_seen=now,
            history=[metrics],
        )
        NODE_STATES[metrics.agent_id] = node
        return node

    # update existing node
    node.last_seen = now
    node.history.append(metrics)
    node.history = _window_history(node)

    history = node.history
    baseline_bps = _compute_baseline_bytes_per_sec(history[:-1]) if len(history) > 1 else 0.0

    # current bytes/sec vs previous sample
    if len(history) >= 2:
        prev = history[-2]
        curr = history[-1]
        dt = (curr.timestamp - prev.timestamp).total_seconds()
        if dt > 0:
            prev_bytes = prev.bytes_sent + prev.bytes_recv
            curr_bytes = curr.bytes_sent + curr.bytes_recv
            current_bps = (curr_bytes - prev_bytes) / dt
        else:
            current_bps = 0.0
    else:
        current_bps = 0.0

    risk = node.risk_score
    alert_msg = None

    # Rule 1: huge spike vs baseline
    if baseline_bps >= MIN_BASELINE_BYTES and current_bps > baseline_bps * SPIKE_MULTIPLIER:
        ratio = current_bps / baseline_bps
        risk = min(MAX_RISK, 50 + (ratio - SPIKE_MULTIPLIER) * 5)
        alert_msg = (
            f"Traffic spike: {current_bps:.0f} B/s vs baseline {baseline_bps:.0f} B/s "
            f"(~{ratio:.1f}x)"
        )

    # Rule 2: node was basically idle, now very loud
    elif baseline_bps < MIN_BASELINE_BYTES and current_bps > 1_000_000:  # ~1 MB/s
        risk = max(risk, 60.0)
        alert_msg = f"Idle node went to high traffic: {current_bps:.0f} B/s"

    # Rule 3: SYN flood–like pattern (many SYNs in this interval)
    if metrics.syn_count is not None and metrics.syn_count > SYN_FLOOD_THRESHOLD:
        risk = max(risk, 80.0)
        msg = f"High SYN rate: {metrics.syn_count} SYN packets in this interval"
        alert_msg = msg if alert_msg is None else alert_msg + " | " + msg

    # Rule 4: Port scan–like behavior (many different destination ports)
    if metrics.unique_dst_ports is not None and metrics.unique_dst_ports > PORT_SCAN_PORT_THRESHOLD:
        risk = max(risk, 70.0)
        msg = f"Possible port scan: {metrics.unique_dst_ports} unique destination ports"
        alert_msg = msg if alert_msg is None else alert_msg + " | " + msg

    # If nothing suspicious, slowly decrease risk
    if alert_msg is None:
        risk = max(0.0, risk - 5.0)

    node.risk_score = risk
    if alert_msg:
        node.last_alert = f"[{now.isoformat()}] {alert_msg}"

    NODE_STATES[node.agent_id] = node
    return node

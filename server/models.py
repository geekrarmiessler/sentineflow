from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime


class AgentMetrics(BaseModel):
    agent_id: str
    hostname: str
    timestamp: datetime
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int

    # new optional fields for attack signals
    syn_count: Optional[int] = None
    unique_dst_ports: Optional[int] = None


class NodeState(BaseModel):
    agent_id: str
    hostname: str
    last_seen: datetime
    history: List[AgentMetrics]
    risk_score: float = 0.0
    last_alert: Optional[str] = None


# simple in-memory "database"
NODE_STATES: Dict[str, NodeState] = {}

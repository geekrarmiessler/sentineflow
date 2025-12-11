from typing import List, Optional
from .models import NODE_STATES, NodeState


def get_all_nodes() -> List[NodeState]:
    return list(NODE_STATES.values())


def get_node(agent_id: str) -> Optional[NodeState]:
    return NODE_STATES.get(agent_id)

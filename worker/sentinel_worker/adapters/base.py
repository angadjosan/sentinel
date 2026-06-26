from abc import ABC, abstractmethod
from dataclasses import dataclass

AUTH_MIDDLEWARE_PATTERNS = ['auth', 'authenticate', 'authorize', 'jwt', 'session', 'passport', 'login_required', 'permission_classes', 'before_action']

@dataclass
class NodeRecord:
    id: str
    kind: str
    name: str
    file: str = ""
    line_start: int | None = None
    line_end: int | None = None
    language: str | None = None
    auth_required: bool = False
    is_entry_point: bool = False
    privilege: str = "anonymous"
    trust_level: str | None = None
    is_sink: bool = False
    taint_uncertain: bool = False
    parse_error: bool = False
    label: str | None = None
    intent: str | None = None

@dataclass
class EdgeRecord:
    src: str
    dst: str
    kind: str
    tainted: bool = False
    sanitized: bool = False
    taint_uncertain: bool = False
    call_uncertainty: str | None = None
    order_index: int | None = None

class FrameworkAdapter(ABC):
    @abstractmethod
    def detect(self, file_path: str, content: str) -> bool:
        ...

    @abstractmethod
    def extract(self, file_path: str, content: str, ast_node_ids: dict) -> tuple[list[NodeRecord], list[EdgeRecord]]:
        """
        Returns (new_nodes, new_edges).
        new_nodes: ROUTE, MIDDLEWARE nodes
        new_edges: GUARDED_BY, CALLS (route->handler)
        GUARDED_BY edges MUST carry order_index.
        """
        ...

    def _is_auth_middleware(self, name: str) -> bool:
        name_lower = name.lower()
        return any(pat in name_lower for pat in AUTH_MIDDLEWARE_PATTERNS)

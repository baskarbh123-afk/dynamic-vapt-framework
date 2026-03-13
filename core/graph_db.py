"""
core/graph_db.py

Graph-aware knowledge base layer.
Extends the flat JSON knowledge base with relationship queries,
adjacency traversal, and attack-chain path finding.

Implements the graph schema from ARCHITECTURE.md § 3 "Intelligent Asset Graph"
without requiring an external Neo4j installation. Uses an in-memory adjacency
structure backed by the existing JSON knowledge base files.

When a real Neo4j instance is available, set NEO4J_URI in config to enable
full Cypher query support.
"""

import json
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Node / Edge types (mirrors the graph schema in ARCHITECTURE.md)
# ------------------------------------------------------------------

NODE_TYPES = {
    "Domain", "Subdomain", "IPAddress", "Port", "Endpoint",
    "Parameter", "AuthMechanism", "Vulnerability", "PoCResult",
    "AttackChain", "Technology", "Certificate", "Secret", "JSFile",
}

EDGE_TYPES = {
    "HAS_SUBDOMAIN", "RESOLVES_TO", "HAS_PORT", "HAS_ENDPOINT",
    "ACCEPTS_PARAMETER", "PROTECTED_BY", "HAS_VULNERABILITY",
    "VALIDATED_BY", "LEADS_TO", "PART_OF", "RUNS", "LOADS_JS",
    "EXPOSES_SECRET", "HAS_SINK", "ISSUES_TOKEN_TYPE",
}


# ------------------------------------------------------------------
# Graph primitives
# ------------------------------------------------------------------

@dataclass
class Node:
    node_id: str
    node_type: str
    properties: dict = field(default_factory=dict)

    def get(self, key: str, default=None):
        return self.properties.get(key, default)


@dataclass
class Edge:
    source_id: str
    target_id: str
    edge_type: str
    properties: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple:
        return (self.source_id, self.edge_type, self.target_id)


# ------------------------------------------------------------------
# Main graph database class
# ------------------------------------------------------------------

class GraphDB:
    """
    In-memory directed property graph backed by JSON persistence.

    Supports:
    - Node and edge CRUD
    - Neighbour traversal (incoming / outgoing)
    - BFS/DFS path finding
    - Pattern matching (find nodes by type + property filter)
    - Attack chain detection

    Usage:
        graph = GraphDB(data_dir="data")
        graph.load()

        domain_id = graph.add_node("Domain", {"name": "example.com"})
        sub_id = graph.add_node("Subdomain", {"name": "api.example.com"})
        graph.add_edge(domain_id, sub_id, "HAS_SUBDOMAIN")

        # Find all subdomains of example.com
        subs = graph.outgoing(domain_id, edge_type="HAS_SUBDOMAIN")
    """

    def __init__(self, data_dir: str = "data"):
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._graph_file = self._data_dir / "graph.json"

        # Adjacency: node_id → list of Edge (outgoing)
        self._out_edges: dict[str, list[Edge]] = defaultdict(list)
        # Reverse index: node_id → list of Edge (incoming)
        self._in_edges: dict[str, list[Edge]] = defaultdict(list)
        # Node store
        self._nodes: dict[str, Node] = {}
        # Edge deduplication set
        self._edge_keys: set[tuple] = set()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self):
        """Load graph from JSON file."""
        if not self._graph_file.exists():
            logger.debug("[GraphDB] No existing graph file — starting empty.")
            return

        try:
            with open(self._graph_file) as f:
                data = json.load(f)
            for node_data in data.get("nodes", []):
                node = Node(**node_data)
                self._nodes[node.node_id] = node
            for edge_data in data.get("edges", []):
                edge = Edge(**edge_data)
                self._register_edge(edge)
            logger.info(
                f"[GraphDB] Loaded {len(self._nodes)} nodes, "
                f"{len(self._edge_keys)} edges from {self._graph_file}"
            )
        except Exception as e:
            logger.warning(f"[GraphDB] Failed to load graph: {e}")

    def save(self):
        """Persist graph to JSON file."""
        all_edges: list[Edge] = []
        for edges in self._out_edges.values():
            all_edges.extend(edges)

        data = {
            "nodes": [
                {"node_id": n.node_id, "node_type": n.node_type, "properties": n.properties}
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "source_id": e.source_id,
                    "target_id": e.target_id,
                    "edge_type": e.edge_type,
                    "properties": e.properties,
                }
                for e in all_edges
            ],
        }
        with open(self._graph_file, "w") as f:
            json.dump(data, f, indent=2)

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def add_node(self, node_type: str, properties: dict, node_id: Optional[str] = None) -> str:
        """
        Add a node to the graph. Returns node_id.
        If a node with the same node_id already exists, its properties are merged.
        """
        if node_type not in NODE_TYPES:
            logger.warning(f"[GraphDB] Unknown node type: {node_type}")

        if node_id is None:
            # Generate deterministic ID from type + key properties
            key_prop = properties.get("name") or properties.get("url") or properties.get("id", "")
            node_id = f"{node_type.lower()}:{_hash(f'{node_type}:{key_prop}')}"

        if node_id in self._nodes:
            # Merge properties
            self._nodes[node_id].properties.update(properties)
        else:
            self._nodes[node_id] = Node(node_id=node_id, node_type=node_type, properties=properties)

        return node_id

    def get_node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def update_node(self, node_id: str, properties: dict):
        if node_id in self._nodes:
            self._nodes[node_id].properties.update(properties)

    def find_nodes(
        self,
        node_type: Optional[str] = None,
        **property_filters,
    ) -> list[Node]:
        """Find all nodes matching type and/or property filters."""
        results = []
        for node in self._nodes.values():
            if node_type and node.node_type != node_type:
                continue
            if all(node.properties.get(k) == v for k, v in property_filters.items()):
                results.append(node)
        return results

    def node_count(self, node_type: Optional[str] = None) -> int:
        if node_type:
            return sum(1 for n in self._nodes.values() if n.node_type == node_type)
        return len(self._nodes)

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        properties: Optional[dict] = None,
    ) -> Edge:
        """Add a directed edge. Silently deduplicates."""
        if edge_type not in EDGE_TYPES:
            logger.warning(f"[GraphDB] Unknown edge type: {edge_type}")

        edge = Edge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            properties=properties or {},
        )

        if edge.key not in self._edge_keys:
            self._register_edge(edge)

        return edge

    def _register_edge(self, edge: Edge):
        self._out_edges[edge.source_id].append(edge)
        self._in_edges[edge.target_id].append(edge)
        self._edge_keys.add(edge.key)

    def outgoing(
        self, node_id: str, edge_type: Optional[str] = None
    ) -> list[Node]:
        """Return nodes reachable via outgoing edges from node_id."""
        edges = self._out_edges.get(node_id, [])
        if edge_type:
            edges = [e for e in edges if e.edge_type == edge_type]
        return [self._nodes[e.target_id] for e in edges if e.target_id in self._nodes]

    def incoming(
        self, node_id: str, edge_type: Optional[str] = None
    ) -> list[Node]:
        """Return nodes that have edges pointing INTO node_id."""
        edges = self._in_edges.get(node_id, [])
        if edge_type:
            edges = [e for e in edges if e.edge_type == edge_type]
        return [self._nodes[e.source_id] for e in edges if e.source_id in self._nodes]

    def edges_between(
        self, source_id: str, target_id: str
    ) -> list[Edge]:
        """Return all edges between two specific nodes."""
        return [
            e for e in self._out_edges.get(source_id, [])
            if e.target_id == target_id
        ]

    # ------------------------------------------------------------------
    # Graph traversal
    # ------------------------------------------------------------------

    def bfs(
        self,
        start_id: str,
        edge_type: Optional[str] = None,
        max_depth: int = 10,
    ) -> Iterator[tuple[Node, int]]:
        """
        Breadth-first traversal from start_id.
        Yields (node, depth) tuples.
        """
        visited = {start_id}
        queue = deque([(start_id, 0)])

        while queue:
            node_id, depth = queue.popleft()
            node = self._nodes.get(node_id)
            if node:
                yield node, depth

            if depth >= max_depth:
                continue

            for neighbour in self.outgoing(node_id, edge_type=edge_type):
                if neighbour.node_id not in visited:
                    visited.add(neighbour.node_id)
                    queue.append((neighbour.node_id, depth + 1))

    def shortest_path(
        self,
        start_id: str,
        end_id: str,
        edge_type: Optional[str] = None,
    ) -> Optional[list[Node]]:
        """
        Find the shortest path between two nodes using BFS.
        Returns list of nodes from start to end, or None if unreachable.
        """
        if start_id not in self._nodes or end_id not in self._nodes:
            return None
        if start_id == end_id:
            return [self._nodes[start_id]]

        visited = {start_id}
        queue = deque([(start_id, [start_id])])

        while queue:
            node_id, path = queue.popleft()
            for neighbour in self.outgoing(node_id, edge_type=edge_type):
                if neighbour.node_id in visited:
                    continue
                new_path = path + [neighbour.node_id]
                if neighbour.node_id == end_id:
                    return [self._nodes[nid] for nid in new_path if nid in self._nodes]
                visited.add(neighbour.node_id)
                queue.append((neighbour.node_id, new_path))

        return None

    # ------------------------------------------------------------------
    # Attack chain specific queries
    # ------------------------------------------------------------------

    def find_vulnerabilities_by_type(self, vuln_type: str) -> list[Node]:
        """Find all verified vulnerability nodes of a given type."""
        return self.find_nodes(
            node_type="Vulnerability",
            type=vuln_type,
        )

    def find_chained_vulnerabilities(
        self,
        start_vuln_id: str,
        max_depth: int = 5,
    ) -> list[list[Node]]:
        """
        Find all vulnerability chains starting from a given vulnerability.
        Traverses LEADS_TO edges to discover attack chains.

        Returns list of chains (each chain is a list of Vulnerability nodes).
        """
        chains: list[list[Node]] = []
        stack = [(start_vuln_id, [start_vuln_id])]

        while stack:
            current_id, path = stack.pop()
            if len(path) > max_depth:
                continue

            next_vulns = self.outgoing(current_id, edge_type="LEADS_TO")

            if not next_vulns:
                # End of chain — record it if multi-step
                if len(path) > 1:
                    chain_nodes = [self._nodes[nid] for nid in path if nid in self._nodes]
                    chains.append(chain_nodes)
            else:
                for vuln in next_vulns:
                    if vuln.node_id not in path:  # avoid cycles
                        stack.append((vuln.node_id, path + [vuln.node_id]))

        return chains

    def get_attack_surface(self, domain_id: str) -> dict:
        """
        Return a structured attack surface map for a domain.
        Traverses: Domain → Subdomains → Endpoints → Vulnerabilities
        """
        surface: dict[str, Any] = {
            "domain": self.get_node(domain_id),
            "subdomains": [],
            "total_endpoints": 0,
            "total_vulnerabilities": 0,
            "critical_paths": [],
        }

        for subdomain in self.outgoing(domain_id, edge_type="HAS_SUBDOMAIN"):
            sub_data: dict[str, Any] = {
                "node": subdomain,
                "endpoints": [],
            }
            for endpoint in self.outgoing(subdomain.node_id, edge_type="HAS_ENDPOINT"):
                ep_data: dict[str, Any] = {
                    "node": endpoint,
                    "vulnerabilities": self.outgoing(endpoint.node_id, edge_type="HAS_VULNERABILITY"),
                }
                sub_data["endpoints"].append(ep_data)
                surface["total_endpoints"] += 1
                surface["total_vulnerabilities"] += len(ep_data["vulnerabilities"])

            surface["subdomains"].append(sub_data)

        return surface

    def stats(self) -> dict:
        """Return graph statistics."""
        type_counts: dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            type_counts[node.node_type] += 1

        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edge_keys),
            "node_type_counts": dict(type_counts),
        }


# ------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------

def _hash(value: str, length: int = 8) -> str:
    import hashlib
    return hashlib.md5(value.encode()).hexdigest()[:length]


# ------------------------------------------------------------------
# Graph sync: write KB records into the graph
# ------------------------------------------------------------------

class GraphSyncWorker:
    """
    Syncs records from the KnowledgeBase JSON files into the GraphDB.
    Runs after each pipeline stage to keep the graph up to date.
    """

    def __init__(self, kb, graph: GraphDB):
        self.kb = kb
        self.graph = graph

    def sync_assets(self):
        """Sync assets.json → Domain/Subdomain/Technology nodes."""
        for asset in self.kb.get_all("assets"):
            asset_type = asset.get("type", "subdomain")
            if asset_type == "subdomain":
                sub_id = self.graph.add_node("Subdomain", {
                    "name": asset.get("subdomain") or asset.get("domain", ""),
                    "ip": asset.get("ip", ""),
                    "status": asset.get("status", ""),
                })
                # Link to parent domain
                domain_name = asset.get("domain", "")
                if domain_name:
                    domain_id = self.graph.add_node("Domain", {"name": domain_name})
                    self.graph.add_edge(domain_id, sub_id, "HAS_SUBDOMAIN")

            elif asset_type == "technology":
                host = asset.get("host", "")
                tech_id = self.graph.add_node("Technology", {
                    "name": asset.get("technology", ""),
                    "version": asset.get("version", ""),
                })
                sub_id = self.graph.add_node("Subdomain", {"name": host})
                self.graph.add_edge(sub_id, tech_id, "RUNS")

    def sync_endpoints(self):
        """Sync endpoints.json → Endpoint nodes."""
        for ep in self.kb.get_all("endpoints"):
            ep_id = self.graph.add_node("Endpoint", {
                "url": ep.get("url", ""),
                "method": ep.get("method", "GET"),
                "status_code": ep.get("status_code"),
                "auth_required": ep.get("auth_required", False),
            })
            # Link endpoint to its subdomain
            from urllib.parse import urlparse
            try:
                host = urlparse(ep.get("url", "")).netloc
                if host:
                    sub_id = self.graph.add_node("Subdomain", {"name": host})
                    self.graph.add_edge(sub_id, ep_id, "HAS_ENDPOINT")
            except Exception:
                pass

    def sync_vulnerabilities(self):
        """Sync vulnerabilities.json → Vulnerability nodes + HAS_VULNERABILITY edges."""
        for vuln in self.kb.get_all("vulnerabilities"):
            vuln_id = self.graph.add_node("Vulnerability", {
                "id": vuln.get("id", ""),
                "title": vuln.get("title", ""),
                "type": vuln.get("type", ""),
                "severity": vuln.get("severity", ""),
                "cvss": vuln.get("cvss", 0.0),
                "status": vuln.get("status", "DRAFT"),
                "owasp": vuln.get("owasp_category", ""),
                "cwe": vuln.get("cwe", ""),
            })
            # Link to endpoint
            endpoint_url = vuln.get("endpoint", "")
            if endpoint_url:
                ep_id = self.graph.add_node("Endpoint", {"url": endpoint_url})
                self.graph.add_edge(ep_id, vuln_id, "HAS_VULNERABILITY")

    def sync_all(self):
        """Run full sync from KB to graph."""
        self.sync_assets()
        self.sync_endpoints()
        self.sync_vulnerabilities()
        self.graph.save()
        logger.info(f"[GraphSyncWorker] Sync complete. Graph stats: {self.graph.stats()}")

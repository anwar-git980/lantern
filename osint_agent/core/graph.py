"""The entity graph: every node a thing, every edge the reason we believe it.

A node is an identifier we could pivot on (`email:a@b.test`) or a fact we could not
(`breach:Adobe`). An edge always records which module produced it and the URL that backs it,
so any claim in the final report can be traced to the request that produced it.
"""

import inspect
import json
from pathlib import Path

import networkx as nx

from osint_agent.core.extract import Candidate
from osint_agent.core.models import Finding, Seed
from osint_agent.core.scoring import Correlation, combine, decay, label, profile_of

# Findings whose value already names an identifier the graph tracks as its own node type.
IDENTIFIER_TYPES = frozenset({"email", "username", "phone", "domain", "name"})


def _link_kwargs() -> dict:
    """networkx 3.4+ warns unless the edge collection name is explicit; 2.x has no such
    parameter. Pinning it keeps a saved graph.json readable across both."""
    if "edges" in inspect.signature(nx.node_link_data).parameters:
        return {"edges": "links"}
    return {}


def seed_node_id(seed: Seed) -> str:
    return f"{seed.type.value}:{seed.normalized}"


def finding_node_id(finding: Finding) -> str:
    return f"{finding.entity_type}:{finding.value}"


class EntityGraph:
    """A MultiDiGraph plus the confidence bookkeeping merging needs."""

    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()

    def _touch(
        self,
        node_id: str,
        *,
        node_type: str,
        value: str,
        depth: int,
        module: str,
        confidence: float,
        source_url: str | None,
        raw: dict | None = None,
        certain: bool = False,
    ) -> str:
        """Create or merge a node, then recompute its confidence from every reporter."""
        if node_id not in self.graph:
            self.graph.add_node(
                node_id,
                type=node_type,
                value=value,
                depth=depth,
                sources=[],
                by_module={},
                confidence=0.0,
            )
        node = self.graph.nodes[node_id]

        # The shortest route from the root is the one that describes this node best.
        node["depth"] = min(node["depth"], depth)
        if source_url and source_url not in node["sources"]:
            node["sources"].append(source_url)
        if raw:
            node["raw"] = {**node.get("raw", {}), **raw}

        # Keep the strongest claim per module: two hits from one module are not independent.
        previous = node["by_module"].get(module, 0.0)
        node["by_module"][module] = max(previous, confidence)
        if certain:
            # The root seed was handed to us. It is not an inference, so the 0.99 ceiling that
            # keeps us from ever claiming certainty about a *derived* node does not apply.
            node["certain"] = True
        node["confidence"] = (
            1.0 if node.get("certain") else decay(combine(node["by_module"]), node["depth"])
        )
        return node_id

    def add_seed(self, seed: Seed, *, depth: int = 0, module: str = "seed") -> str:
        """The root seed, or a candidate we chose to investigate. Given to us, so certain."""
        return self._touch(
            seed_node_id(seed),
            node_type=seed.type.value,
            value=seed.normalized,
            depth=depth,
            module=module,
            confidence=1.0 if depth == 0 else 0.0,
            source_url=None,
            certain=depth == 0,
        )

    def add_finding(self, finding: Finding, *, parent_id: str, depth: int) -> str:
        node_id = finding_node_id(finding)
        self._touch(
            node_id,
            node_type=finding.entity_type,
            value=finding.value,
            depth=depth,
            module=finding.module,
            confidence=finding.confidence,
            source_url=finding.source_url,
            raw=finding.raw,
        )
        self.add_relation(
            parent_id,
            node_id,
            module=finding.module,
            relation=_relation_for(finding.entity_type),
            source_url=finding.source_url,
            confidence=finding.confidence,
        )
        return node_id

    def add_candidate(self, candidate: Candidate, *, parent_id: str, depth: int) -> str:
        """An extracted identifier: a node in its own right, linked to what revealed it."""
        node_id = self._touch(
            candidate.node_id,
            node_type=candidate.seed.type.value,
            value=candidate.seed.normalized,
            depth=depth,
            module=candidate.module,
            # An extracted identifier is a lead, not a fact: the finding it came from carries
            # the evidence, and running a module on it is what will confirm or drop it.
            confidence=0.5,
            source_url=candidate.source_url,
        )
        origin = candidate.found_node if candidate.found_node in self.graph else parent_id
        self.add_relation(
            origin,
            node_id,
            module=candidate.module,
            relation="links_to",
            source_url=candidate.source_url,
            confidence=0.5,
        )
        return node_id

    def add_relation(
        self,
        source: str,
        target: str,
        *,
        module: str,
        relation: str,
        source_url: str | None,
        confidence: float,
    ) -> None:
        if source == target or source not in self.graph or target not in self.graph:
            return
        existing = self.graph.get_edge_data(source, target) or {}
        if any(
            data.get("relation") == relation and data.get("module") == module
            for data in existing.values()
        ):
            return
        self.graph.add_edge(
            source,
            target,
            module=module,
            relation=relation,
            source_url=source_url or "",
            confidence=confidence,
        )

    def profiles(self) -> list:
        """One Profile per account node, for correlation."""
        return [
            profile_of(node_id, data.get("raw") or {})
            for node_id, data in self.graph.nodes(data=True)
            if data.get("type") == "account"
        ]

    def apply_correlations(self, correlations: list[Correlation]) -> None:
        """A correlation is another independent reporter: it raises both endpoints and leaves
        an edge saying why."""
        for link in correlations:
            if link.a not in self.graph or link.b not in self.graph:
                continue
            backing = self._first_source(link.a) or self._first_source(link.b)
            for node_id in (link.a, link.b):
                node = self.graph.nodes[node_id]
                key = f"correlation:{link.relation}"
                node["by_module"][key] = max(node["by_module"].get(key, 0.0), link.confidence)
                node["confidence"] = decay(combine(node["by_module"]), node["depth"])
            self.graph.add_edge(
                link.a,
                link.b,
                module="correlation",
                relation=link.relation,
                source_url=backing or "",
                confidence=link.confidence,
                evidence=link.evidence,
            )

    def _first_source(self, node_id: str) -> str | None:
        sources = self.graph.nodes[node_id].get("sources") or []
        return sources[0] if sources else None

    def by_type(self) -> dict[str, list[tuple[str, float]]]:
        """(value, confidence) per node type, strongest first: what the CLI prints."""
        grouped: dict[str, list[tuple[str, float]]] = {}
        for _, data in self.graph.nodes(data=True):
            grouped.setdefault(data.get("type", "?"), []).append(
                (data.get("value", "?"), data.get("confidence", 0.0))
            )
        for values in grouped.values():
            values.sort(key=lambda pair: (-pair[1], pair[0]))
        return dict(sorted(grouped.items()))

    def labelled(self, node_id: str) -> str:
        return label(self.graph.nodes[node_id].get("confidence", 0.0))

    def untraceable_edges(self) -> list[tuple[str, str, dict]]:
        """Edges that would let a claim into the report without a way to check it."""
        return [
            (source, target, data)
            for source, target, data in self.graph.edges(data=True)
            if not data.get("module") and not data.get("source_url")
        ]

    @classmethod
    def from_dict(cls, data: dict) -> "EntityGraph":
        built = cls()
        built.graph = load_dict(data)
        return built

    def to_dict(self) -> dict:
        return nx.node_link_data(self.graph, **_link_kwargs())

    def to_json(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")


def load_dict(data: dict) -> nx.MultiDiGraph:
    return nx.node_link_graph(data, **_link_kwargs())


def load_json(path: Path) -> nx.MultiDiGraph:
    """Read a graph back. Used by the tests and by anything that post-processes a run."""
    return load_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _relation_for(entity_type: str) -> str:
    if entity_type == "breach":
        return "breached_in"
    if entity_type in ("created", "expires", "last_changed", "registrar", "domain_status"):
        return "registered_on"
    if entity_type in ("linked_url", "linked_account", "account"):
        return "links_to"
    return "found_via"

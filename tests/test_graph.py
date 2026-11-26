"""Entity graph tests: merging, traceability and the JSON round trip."""

import networkx as nx
import pytest

from osint_agent.core.extract import Candidate
from osint_agent.core.graph import EntityGraph, load_json
from osint_agent.core.models import Finding, Seed, SeedType
from osint_agent.core.scoring import Correlation

ROOT = Seed(type=SeedType.email, value="Jane@Example.test")


def finding(module, entity_type, value, confidence=0.6, url="https://a.test/1", **raw):
    return Finding(
        module=module,
        entity_type=entity_type,
        value=value,
        source_url=url,
        confidence=confidence,
        raw=raw,
    )


def built():
    graph = EntityGraph()
    root_id = graph.add_seed(ROOT)
    return graph, root_id


def test_the_root_seed_is_normalized_and_certain():
    graph, root_id = built()

    assert root_id == "email:jane@example.test"
    assert graph.graph.nodes[root_id]["confidence"] == pytest.approx(1.0)
    assert graph.graph.nodes[root_id]["depth"] == 0


def test_two_modules_reporting_one_node_merge_their_sources_and_combine_confidence():
    graph, root_id = built()

    graph.add_finding(
        finding("social", "account", "github.com/jdoe", 0.6, "https://github.com/jdoe"),
        parent_id=root_id,
        depth=0,
    )
    graph.add_finding(
        finding("username", "account", "github.com/jdoe", 0.4, "https://github.com/jdoe?tab=x"),
        parent_id=root_id,
        depth=0,
    )

    node = graph.graph.nodes["account:github.com/jdoe"]
    assert node["by_module"] == {"social": 0.6, "username": 0.4}
    # 1 - (1-0.6)(1-0.4) = 0.76
    assert node["confidence"] == pytest.approx(0.76)
    assert node["sources"] == [
        "https://github.com/jdoe",
        "https://github.com/jdoe?tab=x",
    ]


def test_the_same_module_reporting_twice_keeps_its_strongest_claim_only():
    graph, root_id = built()

    graph.add_finding(finding("social", "account", "a", 0.4), parent_id=root_id, depth=0)
    graph.add_finding(finding("social", "account", "a", 0.6), parent_id=root_id, depth=0)

    node = graph.graph.nodes["account:a"]
    assert node["by_module"] == {"social": 0.6}
    assert node["confidence"] == pytest.approx(0.6)


def test_depth_decay_is_applied_and_the_shortest_route_wins():
    graph, root_id = built()

    graph.add_finding(finding("social", "account", "a", 0.8), parent_id=root_id, depth=2)
    deep = graph.graph.nodes["account:a"]["confidence"]
    assert deep == pytest.approx(0.8 * 0.85**2)

    graph.add_finding(finding("social", "account", "a", 0.8), parent_id=root_id, depth=1)
    assert graph.graph.nodes["account:a"]["depth"] == 1
    assert graph.graph.nodes["account:a"]["confidence"] == pytest.approx(0.8 * 0.85)


def test_a_candidate_edge_starts_at_the_finding_that_revealed_it():
    graph, root_id = built()
    graph.add_finding(
        finding("social", "linked_account", "twitter.com/jdoe", url="https://github.com/jdoe"),
        parent_id=root_id,
        depth=0,
    )
    candidate = Candidate(
        seed=Seed(type=SeedType.username, value="jdoe"),
        module="social",
        entity_type="linked_account",
        found_in="linked_account (username)",
        source_url="https://github.com/jdoe",
        found_node="linked_account:twitter.com/jdoe",
    )

    graph.add_candidate(candidate, parent_id=root_id, depth=1)

    assert graph.graph.has_edge("linked_account:twitter.com/jdoe", "username:jdoe")


def test_every_edge_carries_the_module_and_the_url_that_backs_it():
    graph, root_id = built()
    graph.add_finding(finding("email", "breach", "Adobe", 1.0), parent_id=root_id, depth=0)
    graph.add_finding(
        finding("social", "account", "github.com/jdoe", url="https://github.com/jdoe"),
        parent_id=root_id,
        depth=0,
    )

    assert graph.untraceable_edges() == []
    for _, _, data in graph.graph.edges(data=True):
        assert data["module"]
        assert data["source_url"]
        assert data["relation"]


def test_relations_name_what_the_edge_means():
    graph, root_id = built()
    graph.add_finding(finding("email", "breach", "Adobe", 1.0), parent_id=root_id, depth=0)
    graph.add_finding(finding("domain", "created", "2010-01-01", 1.0), parent_id=root_id, depth=0)
    graph.add_finding(
        finding("domain", "open_port", "1.2.3.4:443", 0.8), parent_id=root_id, depth=0
    )

    relations = {target: data["relation"] for _, target, data in graph.graph.edges(data=True)}
    assert relations["breach:Adobe"] == "breached_in"
    assert relations["created:2010-01-01"] == "registered_on"
    assert relations["open_port:1.2.3.4:443"] == "found_via"


def test_a_correlation_raises_both_endpoints_and_leaves_its_reason_on_the_edge():
    graph, root_id = built()
    graph.add_finding(
        finding("username", "account", "a", 0.4, url="https://a.test/p"),
        parent_id=root_id,
        depth=0,
    )
    graph.add_finding(
        finding("username", "account", "b", 0.4, url="https://b.test/p"),
        parent_id=root_id,
        depth=0,
    )
    before = graph.graph.nodes["account:a"]["confidence"]

    graph.apply_correlations(
        [
            Correlation(
                a="account:a",
                b="account:b",
                relation="same_avatar",
                confidence=0.8,
                evidence="avatar phash distance 2",
            )
        ]
    )

    assert graph.graph.nodes["account:a"]["confidence"] > before
    assert graph.graph.nodes["account:b"]["confidence"] > before
    edge = next(
        data
        for _, target, data in graph.graph.edges(data=True)
        if data["relation"] == "same_avatar" and target == "account:b"
    )
    assert edge["evidence"] == "avatar phash distance 2"
    assert edge["source_url"] == "https://a.test/p"


def test_a_correlation_naming_an_unknown_node_is_ignored():
    graph, _ = built()

    graph.apply_correlations(
        [
            Correlation(
                a="account:ghost", b="account:other", relation="x", confidence=0.9, evidence=""
            )
        ]
    )

    assert graph.graph.number_of_edges() == 0


def test_the_graph_round_trips_through_node_link_json(tmp_path):
    graph, root_id = built()
    graph.add_finding(
        finding("social", "account", "github.com/jdoe", url="https://github.com/jdoe"),
        parent_id=root_id,
        depth=0,
    )
    graph.add_finding(finding("email", "breach", "Adobe", 1.0), parent_id=root_id, depth=1)
    path = tmp_path / "graph.json"

    graph.to_json(path)
    reloaded = load_json(path)

    assert isinstance(reloaded, nx.MultiDiGraph)
    assert set(reloaded.nodes) == set(graph.graph.nodes)
    assert reloaded.number_of_edges() == graph.graph.number_of_edges()
    assert reloaded.nodes[root_id]["value"] == "jane@example.test"
    for _, _, data in reloaded.edges(data=True):
        assert data["module"]
        assert data["source_url"]


def test_nodes_are_grouped_by_type_strongest_first():
    graph, root_id = built()
    graph.add_finding(finding("social", "account", "weak", 0.3), parent_id=root_id, depth=0)
    graph.add_finding(finding("social", "account", "strong", 0.9), parent_id=root_id, depth=0)

    grouped = graph.by_type()

    assert [value for value, _ in grouped["account"]] == ["strong", "weak"]
    assert graph.labelled("account:strong") == "strong"
    assert graph.labelled("account:weak") == "possible"


def test_a_self_edge_is_never_recorded():
    graph, root_id = built()

    graph.add_relation(
        root_id,
        root_id,
        module="social",
        relation="links_to",
        source_url="https://a.test",
        confidence=0.5,
    )

    assert graph.graph.number_of_edges() == 0

"""
tests/test_stage_9_containment.py
====================================
Comprehensive test suite for Stage 9 — Freeze-Graph Min-Cut Containment
Engine.

Test Categories:
    1. TestMinCutResult        (5 tests) — frozen dataclass invariants
    2. TestGraphCutEngine     (15 tests) — Edmonds-Karp min-cut, boundary nodes
    3. TestProcessFreezer     (15 tests) — freeze/release state machine, dry-run
    4. TestContainmentEngine  (15 tests) — orchestrator, audit log, stats
    5. TestIntegration        (10 tests) — end-to-end with real DBRGManager + Stage 7

Total: 60 tests
"""

import sys
import time
from pathlib import Path

import pytest
import networkx as nx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.stage_9_containment.graph_cut import (
    GraphCutEngine,
    MinCutResult,
    _SUPER_SINK,
)
from src.stage_9_containment.process_freezer import (
    ContainmentAction,
    ContainmentState,
    FreezeResult,
    ProcessFreezer,
)
from src.stage_9_containment.containment_engine import (
    ContainmentEngine,
    ContainmentRecord,
)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def build_test_graph(
    process_id="pid:1234",
    file_targets=None,
    edge_costs=None,
    pid_int=1234,
):
    """Build a simple DBRG-like DiGraph for testing."""
    g = nx.DiGraph()
    if file_targets is None:
        file_targets = [
            "file:/tmp/a.txt",
            "file:/tmp/b.xlsx",
            "file:/tmp/c.pdf",
        ]
    if edge_costs is None:
        edge_costs = [1.0] * len(file_targets)

    g.add_node(process_id, node_type="process", pid=pid_int)
    for ft, cost in zip(file_targets, edge_costs):
        g.add_node(ft, node_type="file")
        g.add_edge(
            process_id,
            ft,
            weight=cost,
            cut_cost=cost,
            last_seen=time.time(),
            event_count=1,
        )
    return g


def build_diamond_graph():
    """
    Build a graph with two file targets of different costs.

        pid:100 ──(cost=5.0)──► file:expensive.pdf
        pid:100 ──(cost=1.0)──► file:cheap.txt

    The min-cut should sever both edges (star topology) with total
    cost = 6.0 and both files isolated.
    """
    g = nx.DiGraph()
    g.add_node("pid:100", node_type="process", pid=100)
    g.add_node("file:expensive.pdf", node_type="file")
    g.add_node("file:cheap.txt", node_type="file")

    g.add_edge("pid:100", "file:expensive.pdf", cut_cost=5.0, weight=5.0)
    g.add_edge("pid:100", "file:cheap.txt", cut_cost=1.0, weight=1.0)

    return g


# ═══════════════════════════════════════════════════════════════════════
# 1. MinCutResult — Frozen Dataclass
# ═══════════════════════════════════════════════════════════════════════

class TestMinCutResult:
    """Tests for the MinCutResult frozen dataclass."""

    def test_default_values(self):
        """Default MinCutResult should have zero cut value and empty collections."""
        result = MinCutResult()
        assert result.cut_value == 0.0
        assert result.cut_edges == ()
        assert result.reachable_from_source == frozenset()
        assert result.isolated_files == frozenset()
        assert result.boundary_files == frozenset()

    def test_frozen_immutability(self):
        """MinCutResult should be immutable (frozen dataclass)."""
        result = MinCutResult(cut_value=5.0)
        with pytest.raises(AttributeError):
            result.cut_value = 10.0

    def test_custom_values(self):
        """MinCutResult should store custom values correctly."""
        edges = (("pid:1", "file:a"), ("pid:1", "file:b"))
        result = MinCutResult(
            cut_value=2.5,
            cut_edges=edges,
            reachable_from_source=frozenset({"pid:1"}),
            isolated_files=frozenset({"file:a", "file:b"}),
            boundary_files=frozenset({"file:a", "file:b"}),
        )
        assert result.cut_value == pytest.approx(2.5)
        assert len(result.cut_edges) == 2
        assert len(result.isolated_files) == 2

    def test_equality(self):
        """Two MinCutResults with identical data should be equal."""
        r1 = MinCutResult(cut_value=1.0, cut_edges=(("a", "b"),))
        r2 = MinCutResult(cut_value=1.0, cut_edges=(("a", "b"),))
        assert r1 == r2

    def test_hashable(self):
        """MinCutResult (frozen dataclass) should be hashable."""
        r = MinCutResult(cut_value=1.0)
        assert isinstance(hash(r), int)


# ═══════════════════════════════════════════════════════════════════════
# 2. GraphCutEngine
# ═══════════════════════════════════════════════════════════════════════

class TestGraphCutEngine:
    """Tests for the Edmonds-Karp min-cut engine."""

    def test_empty_graph_returns_empty_cut(self):
        """An empty graph should yield an empty MinCutResult."""
        engine = GraphCutEngine()
        result = engine.compute_min_cut(nx.DiGraph(), "pid:999")
        assert result.cut_value == 0.0
        assert result.cut_edges == ()

    def test_source_not_in_graph(self):
        """A source node not in the graph should yield an empty cut."""
        engine = GraphCutEngine()
        g = build_test_graph()
        result = engine.compute_min_cut(g, "pid:9999")
        assert result.cut_value == 0.0
        assert len(result.cut_edges) == 0

    def test_single_process_single_file_cut(self):
        """A single process→file edge should produce a cut of that edge."""
        engine = GraphCutEngine()
        g = build_test_graph(
            file_targets=["file:/tmp/only.txt"],
            edge_costs=[2.5],
        )
        result = engine.compute_min_cut(g, "pid:1234")
        assert result.cut_value == pytest.approx(2.5)
        assert len(result.cut_edges) == 1
        assert ("pid:1234", "file:/tmp/only.txt") in result.cut_edges

    def test_single_process_multiple_files_cut(self):
        """All direct file edges should be cut for a simple star graph."""
        engine = GraphCutEngine()
        files = ["file:/a.txt", "file:/b.txt", "file:/c.txt"]
        g = build_test_graph(file_targets=files, edge_costs=[1.0, 2.0, 3.0])
        result = engine.compute_min_cut(g, "pid:1234")
        assert result.cut_value == pytest.approx(6.0)
        assert len(result.cut_edges) == 3

    def test_cut_value_equals_sum_of_cut_costs(self):
        """Cut value should equal the sum of cut_cost on severed edges."""
        engine = GraphCutEngine()
        g = build_test_graph(
            file_targets=["file:/x", "file:/y"],
            edge_costs=[1.5, 2.5],
        )
        result = engine.compute_min_cut(g, "pid:1234")
        assert result.cut_value == pytest.approx(4.0)

    def test_cut_isolates_files_from_process(self):
        """After the cut, all boundary files should appear in isolated_files."""
        engine = GraphCutEngine()
        files = ["file:/a.txt", "file:/b.txt"]
        g = build_test_graph(file_targets=files)
        result = engine.compute_min_cut(g, "pid:1234")
        assert result.isolated_files == frozenset(files)

    def test_boundary_nodes_returns_direct_neighbors(self):
        """compute_boundary_nodes should return only direct file successors."""
        engine = GraphCutEngine()
        g = build_test_graph(file_targets=["file:/a", "file:/b"])
        boundary = engine.compute_boundary_nodes(g, "pid:1234")
        assert boundary == {"file:/a", "file:/b"}

    def test_boundary_nodes_empty_for_unknown_pid(self):
        """compute_boundary_nodes should return empty set for unknown PID."""
        engine = GraphCutEngine()
        g = build_test_graph()
        boundary = engine.compute_boundary_nodes(g, "pid:unknown")
        assert boundary == set()

    def test_process_with_no_edges_returns_empty_cut(self):
        """A process node with no outgoing edges yields no cut."""
        engine = GraphCutEngine()
        g = nx.DiGraph()
        g.add_node("pid:1234", node_type="process")
        result = engine.compute_min_cut(g, "pid:1234")
        assert result.cut_value == 0.0
        assert result.boundary_files == frozenset()

    def test_multi_process_graph_only_cuts_target(self):
        """Cutting PID A should not affect PID B's edges."""
        engine = GraphCutEngine()
        g = nx.DiGraph()
        g.add_node("pid:100", node_type="process", pid=100)
        g.add_node("pid:200", node_type="process", pid=200)
        g.add_node("file:/shared", node_type="file")
        g.add_node("file:/only_b", node_type="file")
        g.add_edge("pid:100", "file:/shared", cut_cost=1.0, weight=1.0)
        g.add_edge("pid:200", "file:/shared", cut_cost=1.0, weight=1.0)
        g.add_edge("pid:200", "file:/only_b", cut_cost=1.0, weight=1.0)

        result = engine.compute_min_cut(g, "pid:100")
        # Should only cut pid:100 → file:/shared
        cut_sources = {src for src, _ in result.cut_edges}
        assert "pid:200" not in cut_sources

    def test_diamond_graph_optimal_cut(self):
        """
        In a multi-file graph with varying costs, the min-cut should
        sever all process→file edges with correct total cost.
        """
        engine = GraphCutEngine()
        g = build_diamond_graph()
        result = engine.compute_min_cut(g, "pid:100")
        assert result.cut_value == pytest.approx(6.0)
        assert len(result.isolated_files) == 2
        assert "file:expensive.pdf" in result.isolated_files
        assert "file:cheap.txt" in result.isolated_files

    def test_graph_not_mutated_after_cut(self):
        """The input graph should not be mutated by compute_min_cut."""
        engine = GraphCutEngine()
        g = build_test_graph()
        original_nodes = set(g.nodes)
        original_edges = set(g.edges)
        engine.compute_min_cut(g, "pid:1234")
        assert set(g.nodes) == original_nodes
        assert set(g.edges) == original_edges
        assert _SUPER_SINK not in g.nodes

    def test_custom_capacity_attr(self):
        """Engine should use a custom capacity attribute when specified."""
        engine = GraphCutEngine()
        g = nx.DiGraph()
        g.add_node("pid:1", node_type="process", pid=1)
        g.add_node("file:/a", node_type="file")
        g.add_edge("pid:1", "file:/a", my_cap=7.0, weight=1.0)
        result = engine.compute_min_cut(g, "pid:1", capacity_attr="my_cap")
        assert result.cut_value == pytest.approx(7.0)

    def test_cut_edges_are_valid_graph_edges(self):
        """Every cut edge should exist in the original graph."""
        engine = GraphCutEngine()
        g = build_test_graph()
        result = engine.compute_min_cut(g, "pid:1234")
        for u, v in result.cut_edges:
            assert g.has_edge(u, v), f"Cut edge ({u}, {v}) not in graph"

    def test_total_cuts_counter(self):
        """total_cuts_computed should increment per successful cut."""
        engine = GraphCutEngine()
        g = build_test_graph()
        assert engine.total_cuts_computed == 0
        engine.compute_min_cut(g, "pid:1234")
        assert engine.total_cuts_computed == 1
        engine.compute_min_cut(g, "pid:1234")
        assert engine.total_cuts_computed == 2


# ═══════════════════════════════════════════════════════════════════════
# 3. ProcessFreezer
# ═══════════════════════════════════════════════════════════════════════

class TestProcessFreezer:
    """Tests for the kernel process suspension manager."""

    def test_default_dry_run_mode(self):
        """ProcessFreezer should default to dry_run=True."""
        freezer = ProcessFreezer()
        assert freezer.dry_run is True

    def test_freeze_returns_success(self):
        """freeze() should succeed for a never-seen PID."""
        freezer = ProcessFreezer()
        result = freezer.freeze(pid=1234, reason="test")
        assert result.success is True
        assert result.action == "FREEZE"

    def test_freeze_sets_frozen_state(self):
        """After freeze(), get_state() should return FROZEN."""
        freezer = ProcessFreezer()
        freezer.freeze(pid=1234)
        assert freezer.get_state(1234) == ContainmentState.FROZEN

    def test_release_frozen_process(self):
        """release() should succeed for a FROZEN process."""
        freezer = ProcessFreezer()
        freezer.freeze(pid=1234)
        result = freezer.release(pid=1234, reason="false_positive")
        assert result.success is True
        assert result.action == "RELEASE"
        assert freezer.get_state(1234) == ContainmentState.RELEASED

    def test_release_unfrozen_process_fails(self):
        """release() should fail for a process that is not FROZEN."""
        freezer = ProcessFreezer()
        result = freezer.release(pid=9999)
        assert result.success is False
        assert "not FROZEN" in result.error

    def test_double_freeze_fails(self):
        """Freezing an already-frozen process should fail."""
        freezer = ProcessFreezer()
        freezer.freeze(pid=1234)
        result = freezer.freeze(pid=1234)
        assert result.success is False
        assert "already frozen" in result.error.lower()

    def test_get_state_unknown_pid_returns_active(self):
        """get_state() for an unknown PID should return ACTIVE."""
        freezer = ProcessFreezer()
        assert freezer.get_state(7777) == ContainmentState.ACTIVE

    def test_get_frozen_pids(self):
        """get_frozen_pids() should list only FROZEN PIDs."""
        freezer = ProcessFreezer()
        freezer.freeze(pid=100)
        freezer.freeze(pid=200)
        freezer.freeze(pid=300)
        freezer.release(pid=200)
        frozen = freezer.get_frozen_pids()
        assert 100 in frozen
        assert 300 in frozen
        assert 200 not in frozen

    def test_freeze_records_reason(self):
        """Freeze result should carry the reason string."""
        freezer = ProcessFreezer()
        result = freezer.freeze(pid=42, reason="CRITICAL_RISK trust=5.0")
        assert result.reason == "CRITICAL_RISK trust=5.0"

    def test_latency_is_non_negative(self):
        """Freeze latency should be >= 0 ms."""
        freezer = ProcessFreezer()
        result = freezer.freeze(pid=1)
        assert result.latency_ms >= 0.0

    def test_freeze_result_fields(self):
        """FreezeResult should have all expected fields."""
        freezer = ProcessFreezer()
        result = freezer.freeze(pid=42, reason="test")
        assert isinstance(result.pid, int)
        assert isinstance(result.action, str)
        assert isinstance(result.success, bool)
        assert isinstance(result.timestamp, float)
        assert isinstance(result.reason, str)
        assert isinstance(result.dry_run, bool)
        assert isinstance(result.latency_ms, float)

    def test_multiple_pids_independent(self):
        """Freezing one PID should not affect another."""
        freezer = ProcessFreezer()
        freezer.freeze(pid=100)
        freezer.freeze(pid=200)
        assert freezer.get_state(100) == ContainmentState.FROZEN
        assert freezer.get_state(200) == ContainmentState.FROZEN
        freezer.release(pid=100)
        assert freezer.get_state(100) == ContainmentState.RELEASED
        assert freezer.get_state(200) == ContainmentState.FROZEN

    def test_freeze_timestamp_reasonable(self):
        """Freeze timestamp should be a recent time."""
        freezer = ProcessFreezer()
        before = time.time()
        result = freezer.freeze(pid=1)
        after = time.time()
        assert before <= result.timestamp <= after

    def test_total_actions_counter(self):
        """total_actions should count all operations including failures."""
        freezer = ProcessFreezer()
        freezer.freeze(pid=1)        # success: +1
        freezer.freeze(pid=1)        # fail (double freeze): +1
        freezer.release(pid=1)       # success: +1
        freezer.release(pid=1)       # fail (not frozen): +1
        assert freezer.total_actions == 4
        assert freezer.total_freezes == 1
        assert freezer.total_releases == 1

    def test_repr(self):
        """__repr__ should include key state."""
        freezer = ProcessFreezer()
        freezer.freeze(pid=1)
        r = repr(freezer)
        assert "dry_run=True" in r
        assert "frozen=1" in r

    def test_get_all_states(self):
        """get_all_states should return snapshot of all tracked PIDs."""
        freezer = ProcessFreezer()
        freezer.freeze(pid=100)
        freezer.freeze(pid=200)
        freezer.release(pid=200)
        states = freezer.get_all_states()
        assert states[100] == "FROZEN"
        assert states[200] == "RELEASED"


# ═══════════════════════════════════════════════════════════════════════
# 4. ContainmentEngine
# ═══════════════════════════════════════════════════════════════════════

class TestContainmentEngine:
    """Tests for the Stage 9 orchestrator."""

    def test_contain_with_graph(self):
        """contain() should succeed with a valid DBRG graph."""
        engine = ContainmentEngine()
        g = build_test_graph()
        record = engine.contain(pid=1234, dbrg_graph=g)
        assert record.success is True
        assert record.action == "CONTAIN"
        assert record.pid == 1234

    def test_contain_records_history(self):
        """Containment events should appear in the history log."""
        engine = ContainmentEngine()
        g = build_test_graph()
        engine.contain(pid=1234, dbrg_graph=g)
        history = engine.get_containment_history()
        assert len(history) == 1
        assert history[0].pid == 1234

    def test_contain_freezes_process(self):
        """After contain(), the PID should be in FROZEN state."""
        engine = ContainmentEngine()
        g = build_test_graph()
        engine.contain(pid=1234, dbrg_graph=g)
        assert engine.freezer.get_state(1234) == ContainmentState.FROZEN

    def test_contain_computes_cut(self):
        """contain() should compute and record the min-cut."""
        engine = ContainmentEngine()
        g = build_test_graph(edge_costs=[1.0, 2.0, 3.0])
        record = engine.contain(pid=1234, dbrg_graph=g)
        assert record.cut_value == pytest.approx(6.0)
        assert len(record.cut_edges) == 3
        assert len(record.isolated_files) == 3

    def test_contain_latency_measured(self):
        """Containment latency should be positive."""
        engine = ContainmentEngine()
        g = build_test_graph()
        record = engine.contain(pid=1234, dbrg_graph=g)
        assert record.latency_ms > 0.0

    def test_contain_with_trust_state(self):
        """contain() should record trust_at_containment from Stage 7."""
        engine = ContainmentEngine()
        g = build_test_graph()
        trust = {"trust": 5.2, "risk_tier": "CRITICAL_RISK"}
        record = engine.contain(pid=1234, dbrg_graph=g, trust_state=trust)
        assert record.trust_at_containment == pytest.approx(5.2)
        assert record.risk_tier_at_containment == "CRITICAL_RISK"

    def test_contain_without_trust_state(self):
        """contain() should work without a trust_state dict."""
        engine = ContainmentEngine()
        g = build_test_graph()
        record = engine.contain(pid=1234, dbrg_graph=g)
        assert record.trust_at_containment is None
        assert record.risk_tier_at_containment is None

    def test_release_after_contain(self):
        """release() should succeed after contain()."""
        engine = ContainmentEngine()
        g = build_test_graph()
        engine.contain(pid=1234, dbrg_graph=g)
        record = engine.release(pid=1234, reason="false_positive")
        assert record.success is True
        assert record.action == "RELEASE"

    def test_release_without_prior_contain(self):
        """release() without prior contain should fail gracefully."""
        engine = ContainmentEngine()
        record = engine.release(pid=9999)
        assert record.success is False

    def test_containment_history_filter_by_pid(self):
        """get_containment_history(pid=X) should filter correctly."""
        engine = ContainmentEngine()
        g1 = build_test_graph(process_id="pid:100", pid_int=100)
        g2 = build_test_graph(process_id="pid:200", pid_int=200)
        engine.contain(pid=100, dbrg_graph=g1)
        engine.contain(pid=200, dbrg_graph=g2)
        h100 = engine.get_containment_history(pid=100)
        h200 = engine.get_containment_history(pid=200)
        assert len(h100) == 1
        assert len(h200) == 1
        assert h100[0].pid == 100

    def test_stats_counts(self):
        """get_stats() should report correct counts."""
        engine = ContainmentEngine()
        g = build_test_graph()
        engine.contain(pid=1234, dbrg_graph=g)
        stats = engine.get_stats()
        assert stats["total_containments"] == 1
        assert stats["currently_frozen"] == 1
        assert 1234 in stats["frozen_pids"]

    def test_contain_already_frozen_pid(self):
        """Containing an already-frozen PID should fail gracefully."""
        engine = ContainmentEngine()
        g = build_test_graph()
        engine.contain(pid=1234, dbrg_graph=g)
        record = engine.contain(pid=1234, dbrg_graph=g)
        assert record.success is False

    def test_dry_run_default(self):
        """ContainmentEngine should default to dry_run=True."""
        engine = ContainmentEngine()
        assert engine.freezer.dry_run is True

    def test_contain_pid_not_in_graph(self):
        """Containing a PID not present in the graph should still freeze it."""
        engine = ContainmentEngine()
        g = build_test_graph(process_id="pid:9999", pid_int=9999)
        # PID 1234 is not in this graph, but we still freeze it
        record = engine.contain(pid=1234, dbrg_graph=g)
        assert record.success is True
        assert record.cut_value == 0.0
        assert len(record.cut_edges) == 0
        assert engine.freezer.get_state(1234) == ContainmentState.FROZEN

    def test_repr(self):
        """__repr__ should include key stats."""
        engine = ContainmentEngine()
        r = repr(engine)
        assert "containments=0" in r
        assert "dry_run=True" in r


# ═══════════════════════════════════════════════════════════════════════
# 5. Integration Tests
# ═══════════════════════════════════════════════════════════════════════

class TestIntegration:
    """End-to-end integration tests with real Stage 3 and Stage 7."""

    def test_stage7_to_stage9_full_flow(self):
        """
        Build a DBRG, drive trust to CRITICAL_RISK via Stage 7, then
        contain the process through Stage 9.
        """
        from src.stage_7_trust import TrustEvolution

        trust = TrustEvolution()
        containment = ContainmentEngine()

        # Simulate high-intent events that drive trust to zero
        g = build_test_graph()
        for _ in range(5):
            result = trust.evolve({
                "pid": 1234,
                "IntentDrift": 0.95,
                "drift_rate": 0.5,
                "timestamp": time.time(),
            })

        assert result["should_contain"] is True
        assert result["risk_tier"] == "CRITICAL_RISK"

        # Now execute containment
        record = containment.contain(
            pid=1234,
            dbrg_graph=g,
            trust_state=result,
        )
        assert record.success is True
        assert record.trust_at_containment == pytest.approx(result["trust"])
        assert record.risk_tier_at_containment == "CRITICAL_RISK"
        assert len(record.cut_edges) == 3
        assert containment.freezer.get_state(1234) == ContainmentState.FROZEN

    def test_benign_process_not_contained(self):
        """A process that stays SAFE should not trigger containment."""
        from src.stage_7_trust import TrustEvolution

        trust = TrustEvolution()

        result = trust.evolve({
            "pid": 5555,
            "IntentDrift": 0.01,
            "drift_rate": 0.0,
            "timestamp": time.time(),
        })

        assert result["should_contain"] is False
        assert result["risk_tier"] == "SAFE"

    def test_false_positive_recovery(self):
        """Contain → release → verify state goes to RELEASED."""
        containment = ContainmentEngine()
        g = build_test_graph()

        containment.contain(pid=1234, dbrg_graph=g)
        assert containment.freezer.get_state(1234) == ContainmentState.FROZEN

        record = containment.release(pid=1234, reason="analyst_override")
        assert record.success is True
        assert containment.freezer.get_state(1234) == ContainmentState.RELEASED

    def test_multiple_attacks_different_pids(self):
        """Two malicious PIDs should be contained independently."""
        containment = ContainmentEngine()
        g1 = build_test_graph(
            process_id="pid:100",
            pid_int=100,
            file_targets=["file:/a"],
        )
        g2 = build_test_graph(
            process_id="pid:200",
            pid_int=200,
            file_targets=["file:/b"],
        )

        r1 = containment.contain(pid=100, dbrg_graph=g1)
        r2 = containment.contain(pid=200, dbrg_graph=g2)
        assert r1.success is True
        assert r2.success is True
        assert containment.freezer.get_state(100) == ContainmentState.FROZEN
        assert containment.freezer.get_state(200) == ContainmentState.FROZEN

    def test_containment_preserves_other_processes(self):
        """Containing PID A should not change PID B's state."""
        containment = ContainmentEngine()
        g = nx.DiGraph()
        g.add_node("pid:100", node_type="process", pid=100)
        g.add_node("pid:200", node_type="process", pid=200)
        g.add_node("file:/shared", node_type="file")
        g.add_edge("pid:100", "file:/shared", cut_cost=1.0, weight=1.0)
        g.add_edge("pid:200", "file:/shared", cut_cost=1.0, weight=1.0)

        containment.contain(pid=100, dbrg_graph=g)
        assert containment.freezer.get_state(100) == ContainmentState.FROZEN
        assert containment.freezer.get_state(200) == ContainmentState.ACTIVE

    def test_cut_edges_match_dbrg_topology(self):
        """Every cut edge should exist in the original DBRG."""
        containment = ContainmentEngine()
        g = build_test_graph()
        record = containment.contain(pid=1234, dbrg_graph=g)
        for u, v in record.cut_edges:
            assert g.has_edge(u, v), f"Cut edge ({u}, {v}) not in DBRG"

    def test_containment_latency_under_threshold(self):
        """Full containment (cut + freeze) should complete in < 500ms."""
        containment = ContainmentEngine()
        g = build_test_graph()
        record = containment.contain(pid=1234, dbrg_graph=g)
        assert record.latency_ms < 500.0

    def test_stats_integration(self):
        """Stats should reflect all operations after a full sequence."""
        containment = ContainmentEngine()
        g = build_test_graph()
        containment.contain(pid=1234, dbrg_graph=g)
        containment.release(pid=1234)

        stats = containment.get_stats()
        assert stats["total_containments"] == 1
        assert stats["total_releases"] == 1
        assert stats["currently_frozen"] == 0
        assert stats["total_log_entries"] == 2

    def test_contain_with_real_dbrg_manager(self):
        """Use the actual DBRGManager from Stage 3 to build a graph."""
        from src.stage_3_dbrg.dbrg_manager import DBRGManager

        dbrg = DBRGManager(decay_lambda=0.01)
        containment = ContainmentEngine()

        # Simulate events as the real pipeline would
        for i in range(5):
            dbrg.process_event({
                "actorID": "pid:4321",
                "objectID": f"file:/victim/doc_{i}.xlsx",
                "pid": 4321,
                "operation": "FILE_MODIFY",
                "context": {
                    "exe_path": "malware.exe",
                    "parent_exe": "cmd.exe",
                },
            })

        snapshot = dbrg.get_graph_snapshot()
        record = containment.contain(pid=4321, dbrg_graph=snapshot)

        assert record.success is True
        assert record.cut_value > 0.0
        assert len(record.cut_edges) == 5
        assert len(record.isolated_files) == 5
        assert containment.freezer.get_state(4321) == ContainmentState.FROZEN

    def test_full_pipeline_stage7_to_stage9_with_dbrg(self):
        """
        Full end-to-end: build DBRG via real events, run Stage 7 trust
        evolution until CRITICAL_RISK, then execute Stage 9 containment.
        """
        from src.stage_3_dbrg.dbrg_manager import DBRGManager
        from src.stage_7_trust import TrustEvolution

        dbrg = DBRGManager(decay_lambda=0.01)
        trust = TrustEvolution()
        containment = ContainmentEngine()

        # Build DBRG with simulated malicious activity
        for i in range(3):
            dbrg.process_event({
                "actorID": "pid:8888",
                "objectID": f"file:/sensitive/report_{i}.pdf",
                "pid": 8888,
                "operation": "FILE_MODIFY",
                "context": {
                    "exe_path": "ransomware.exe",
                    "parent_exe": "explorer.exe",
                },
            })

        # Drive trust to CRITICAL_RISK
        trust_result = None
        for _ in range(5):
            trust_result = trust.evolve({
                "pid": 8888,
                "IntentDrift": 0.95,
                "drift_rate": 0.8,
                "timestamp": time.time(),
            })

        assert trust_result["should_contain"] is True

        # Execute containment
        snapshot = dbrg.get_graph_snapshot()
        record = containment.contain(
            pid=8888,
            dbrg_graph=snapshot,
            trust_state=trust_result,
        )

        assert record.success is True
        assert record.cut_value > 0.0
        assert len(record.isolated_files) == 3
        assert record.risk_tier_at_containment == "CRITICAL_RISK"
        assert containment.freezer.get_state(8888) == ContainmentState.FROZEN

        # Verify stats
        stats = containment.get_stats()
        assert stats["total_containments"] == 1
        assert stats["currently_frozen"] == 1

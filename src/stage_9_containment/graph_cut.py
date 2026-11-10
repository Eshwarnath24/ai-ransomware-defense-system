"""
src/stage_9_containment/graph_cut.py
========================================
Stage 9 — Freeze-Graph Min-Cut Engine

Computes minimum s-t cuts on the Dynamic Behavior Relationship Graph
(DBRG) using the Edmonds-Karp algorithm (BFS-based Ford-Fulkerson) to
identify the optimal set of edges to sever, isolating a malicious
process node from its file-node targets at minimum total cut cost.

Algorithm
---------
1. Accept a DBRG snapshot (``nx.DiGraph``) and a source process node
   ID (e.g. ``"pid:1234"``).
2. Identify all file nodes reachable from the source (boundary nodes).
3. Create a virtual super-sink ``__SINK__`` connected from every
   boundary file node with infinite capacity.
4. Run ``nx.minimum_cut`` with ``flow_func=edmonds_karp`` using the
   ``cut_cost`` edge attribute as capacity.
5. Return a ``MinCutResult`` describing which edges to sever and which
   file nodes become isolated from the process.

Mathematical Foundation (architecture specification, Stage 9):
    Min-Cut(s, t) = argmin_{C ⊂ E} Σ_{e ∈ C} cut_cost(e)
    subject to: no s→t path exists after removing C
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

import networkx as nx
from networkx.algorithms.flow import edmonds_karp

logger = logging.getLogger(__name__)

# Sentinel node ID for the virtual super-sink
_SUPER_SINK = "__SINK__"

# Default capacity for edges missing the cut_cost attribute
DEFAULT_CAPACITY = 1.0

# Capacity for super-sink edges (effectively infinite)
SINK_CAPACITY = 1_000_000.0


@dataclass(frozen=True)
class MinCutResult:
    """
    Immutable result of a minimum s-t cut computation.

    Attributes
    ----------
    cut_value : float
        Total cost of the cut edges (sum of cut_cost for severed edges).
    cut_edges : tuple
        Tuple of (source, target) pairs representing the edges to sever.
        Uses tuple instead of list for immutability.
    reachable_from_source : frozenset
        Set of node IDs still reachable from the source process after
        the cut is applied.
    isolated_files : frozenset
        Set of file-node IDs that become isolated from the source
        process after the cut (i.e. boundary files minus those still
        reachable).
    boundary_files : frozenset
        Set of all file-node IDs that were directly reachable from the
        source *before* the cut.
    """

    cut_value: float = 0.0
    cut_edges: tuple = ()
    reachable_from_source: frozenset = field(default_factory=frozenset)
    isolated_files: frozenset = field(default_factory=frozenset)
    boundary_files: frozenset = field(default_factory=frozenset)


class GraphCutEngine:
    """
    Computes minimum s-t cuts on the DBRG to optimally isolate a
    malicious process from its file targets.

    The engine never mutates the input graph; it works on a temporary
    copy augmented with a virtual super-sink node.

    Parameters
    ----------
    default_capacity : float
        Fallback capacity for edges that lack a ``cut_cost`` attribute.
    """

    def __init__(self, default_capacity: float = DEFAULT_CAPACITY) -> None:
        self.default_capacity = default_capacity
        self.total_cuts_computed: int = 0

    @staticmethod
    def _resolve_source_node(graph: nx.DiGraph, source_pid: object) -> Optional[object]:
        """
        Resolve and normalize the process node key in the DBRG.

        Handles both canonical DBRG format ('pid:1234') and raw integer (1234).
        Returns the matching node key in the graph, or None if not found.
        """
        if graph.has_node(source_pid):
            return source_pid
        if isinstance(source_pid, int) and graph.has_node(f"pid:{source_pid}"):
            return f"pid:{source_pid}"
        if isinstance(source_pid, str) and source_pid.startswith("pid:") and source_pid[4:].isdigit():
            pid_int = int(source_pid[4:])
            if graph.has_node(pid_int):
                return pid_int
        return None

    def compute_boundary_nodes(
        self, graph: nx.DiGraph, source_pid: str
    ) -> Set[str]:
        """
        Find all file nodes directly reachable from *source_pid*.

        A node is considered a "file" node if its ``node_type`` attribute
        is ``"file"`` or if its ID starts with ``"file:"``.  Only direct
        successors (one hop) are returned.

        Parameters
        ----------
        graph : nx.DiGraph
            The DBRG graph (or a snapshot).
        source_pid : str
            Process node ID, e.g. ``"pid:1234"`` or integer PID.

        Returns
        -------
        set of str
            File-node IDs that are direct successors of *source_pid*.
        """
        source_node = self._resolve_source_node(graph, source_pid)
        if source_node is None:
            return set()

        boundary: Set[str] = set()
        for successor in graph.successors(source_node):
            node_data = graph.nodes.get(successor, {})
            node_type = node_data.get("node_type", "")
            if node_type == "file" or str(successor).startswith("file:"):
                boundary.add(successor)
        return boundary

    def compute_min_cut(
        self,
        graph: nx.DiGraph,
        source_pid: str,
        capacity_attr: str = "cut_cost",
    ) -> MinCutResult:
        """
        Compute the minimum s-t cut isolating *source_pid* from its
        file targets.

        Creates a virtual super-sink connected from every boundary file
        node, runs Edmonds-Karp, and returns the ``MinCutResult``.

        Parameters
        ----------
        graph : nx.DiGraph
            The DBRG graph snapshot. Not mutated.
        source_pid : str
            Process node ID to isolate (the "source" in the s-t cut).
        capacity_attr : str
            Edge attribute name used as capacity (default ``"cut_cost"``).

        Returns
        -------
        MinCutResult
            Describes the optimal cut: value, edges, and isolated files.
        """
        # ── 1. Validate & normalize source exists ────────────────────
        source_node = self._resolve_source_node(graph, source_pid)
        if source_node is None:
            logger.warning(
                "[GraphCut] Source node '%s' not in graph; returning empty cut.",
                source_pid,
            )
            return MinCutResult()

        # ── 2. Find boundary file nodes ──────────────────────────────
        boundary = self.compute_boundary_nodes(graph, source_node)
        if not boundary:
            logger.info(
                "[GraphCut] Source '%s' has no file-node successors; "
                "nothing to cut.",
                source_node,
            )
            return MinCutResult(
                reachable_from_source=frozenset({source_node}),
                boundary_files=frozenset(),
            )

        # ── 3. Build augmented graph with super-sink ─────────────────
        aug = graph.copy()

        # Ensure every edge has a capacity value
        for u, v, data in aug.edges(data=True):
            if capacity_attr not in data:
                data[capacity_attr] = self.default_capacity

        # Add super-sink and connect all boundary files to it
        aug.add_node(_SUPER_SINK, node_type="sink")
        for file_node in boundary:
            aug.add_edge(
                file_node, _SUPER_SINK, **{capacity_attr: SINK_CAPACITY}
            )

        # ── 4. Run Edmonds-Karp min-cut ──────────────────────────────
        try:
            cut_value, (reachable, non_reachable) = nx.minimum_cut(
                aug,
                source_node,
                _SUPER_SINK,
                capacity=capacity_attr,
                flow_func=edmonds_karp,
            )
        except nx.NetworkXError as exc:
            logger.error(
                "[GraphCut] NetworkX error during min-cut for '%s': %s",
                source_node,
                exc,
            )
            return MinCutResult(boundary_files=frozenset(boundary))

        # ── 5. Identify cut edges (exclude super-sink edges) ─────────
        cut_edges: List[Tuple[str, str]] = []
        for u in reachable:
            for v in non_reachable:
                if aug.has_edge(u, v) and v != _SUPER_SINK:
                    cut_edges.append((u, v))

        # ── 6. Determine isolated files ──────────────────────────────
        # Files that were in boundary but are now in non_reachable
        reachable_clean = frozenset(reachable - {_SUPER_SINK})
        isolated = frozenset(boundary & (non_reachable - {_SUPER_SINK}))

        self.total_cuts_computed += 1

        result = MinCutResult(
            cut_value=cut_value,
            cut_edges=tuple(cut_edges),
            reachable_from_source=reachable_clean,
            isolated_files=isolated,
            boundary_files=frozenset(boundary),
        )

        logger.info(
            "[GraphCut] PID=%s  cut_value=%.4f  cut_edges=%d  "
            "isolated_files=%d/%d",
            source_node,
            cut_value,
            len(cut_edges),
            len(isolated),
            len(boundary),
        )

        return result

    def __repr__(self) -> str:
        return f"GraphCutEngine(total_cuts={self.total_cuts_computed})"


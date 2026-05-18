from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class SlowQuery:
    query: str
    mean_ms: float
    calls: int
    total_ms: float
    last_run: Optional[datetime]
    example_plan: Optional[Dict[str, Any]] = None


@dataclass
class IndexSuggestion:
    table: str
    columns: Tuple[str, ...]
    suggestion_sql: str
    reason: str


@dataclass
class OptimizedQuery:
    original: str
    optimized: str
    notes: List[str]


@dataclass
class MaterializedView:
    name: str
    create_sql: str
    refresh_sql: str


def _get_psycopg2_conn(dsn: Optional[str] = None):
    try:
        import psycopg2
        import psycopg2.extras
    except Exception:
        raise RuntimeError('psycopg2 is required for DB operations')
    dsn = dsn or os.environ.get('DATABASE_URL')
    if not dsn:
        raise RuntimeError('DATABASE_URL not set and no dsn provided')
    return psycopg2.connect(dsn)


def analyze_slow_queries(threshold_ms: int = 100, limit: int = 50, dsn: Optional[str] = None) -> List[SlowQuery]:
    """Identify slow queries using pg_stat_statements when available.

    Falls back to an empty list if extension not available.
    """
    results: List[SlowQuery] = []
    try:
        conn = _get_psycopg2_conn(dsn)
        cur = conn.cursor()
        # Ensure pg_stat_statements exists
        cur.execute("SELECT count(*) FROM pg_extension WHERE extname='pg_stat_statements'")
        if cur.fetchone()[0] == 0:
            logger.warning('pg_stat_statements not installed; cannot analyze slow queries')
            return results

        q = shlex.split("""
        SELECT query, calls, total_time, mean_time
        FROM pg_stat_statements
        ORDER BY mean_time DESC
        LIMIT %s
        """)
        # Use plain SQL to avoid sql injection risks for limit
        cur.execute("SELECT query, calls, total_time, mean_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        for row in rows:
            query_text, calls, total_time, mean_time = row
            if mean_time < threshold_ms:
                continue
            # attempt EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
            plan = None
            try:
                cur.execute('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + query_text)
                plan = cur.fetchone()[0][0]
            except Exception:
                plan = None
            results.append(SlowQuery(query=query_text, mean_ms=mean_time, calls=calls, total_ms=total_time, last_run=None, example_plan=plan))
        cur.close()
        conn.close()
    except Exception:
        logger.exception('analyze_slow_queries failed')
    return results


def _extract_seqscan_tables(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    nodes = []

    def walk(node: Dict[str, Any]):
        node_name = node.get('Node Type') or node.get('Plan') or node.get('Node-Type')
        if node.get('Node Type') == 'Seq Scan':
            nodes.append(node)
        for k, v in node.items():
            if isinstance(v, dict):
                walk(v)
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, dict):
                        walk(it)

    walk(plan)
    return nodes


def suggest_indexes(slow_queries: List[SlowQuery], dsn: Optional[str] = None) -> List[IndexSuggestion]:
    """Generate naive index suggestions based on EXPLAIN plans (look for Seq Scan filters).

    This is heuristic and should be reviewed by DBAs before applying.
    """
    suggestions: List[IndexSuggestion] = []
    for sq in slow_queries:
        plan = sq.example_plan
        if not plan:
            continue
        try:
            seq_nodes = _extract_seqscan_tables(plan)
            for node in seq_nodes:
                relation = node.get('Relation Name') or node.get('Relation-Name')
                filter_cond = node.get('Filter') or node.get('Filter\n') or node.get('Index Cond')
                if not relation or not filter_cond:
                    continue
                # crude extraction of column names from filter condition
                cols = tuple(set(re.findall(r"([a-zA-Z_][a-zA-Z0-9_]+)\s*=", str(filter_cond))))
                if not cols:
                    continue
                cols = tuple(cols)
                idx_name = f"ix_{relation}_{'_'.join(cols)}"
                sql = f'CREATE INDEX CONCURRENTLY IF NOT EXISTS {idx_name} ON {relation} ({", ".join(cols)});'
                reason = f'Seq Scan on {relation} with filter {filter_cond}'
                suggestions.append(IndexSuggestion(table=relation, columns=cols, suggestion_sql=sql, reason=reason))
        except Exception:
            logger.exception('suggest_indexes failed for query')
    return suggestions


def optimize_query(query: str) -> OptimizedQuery:
    """Apply simple, safe rewrites and suggest prepared statement usage.

    This function is conservative: it returns suggested optimized SQL and notes.
    """
    notes: List[str] = []
    optimized = query.strip()
    # Suggest prepared Statement pattern (use $1 placeholders for PostgreSQL)
    # Replace literal values with placeholders heuristically
    literals = re.findall(r"'(.*?)'", optimized)
    if literals:
        notes.append('Found string literals; consider using prepared statements')
        # naive placeholder replacement (only visual suggestion)
        for i, lit in enumerate(literals, start=1):
            optimized = optimized.replace(f"'{lit}'", f'${i}', 1)
    # Suggest removing SELECT *
    if re.search(r"SELECT\s+\*", optimized, re.IGNORECASE):
        notes.append('Query uses SELECT *; list required columns to reduce I/O')
    # Suggest LIMIT for queries that likely need paging
    if not re.search(r"LIMIT\s+\d+", optimized, re.IGNORECASE) and re.search(r"ORDER\s+BY", optimized, re.IGNORECASE):
        notes.append('Consider adding LIMIT for paginated queries')

    return OptimizedQuery(original=query, optimized=optimized, notes=notes)


def create_materialized_views(queries: List[str], schema: str = 'public') -> List[MaterializedView]:
    mvs: List[MaterializedView] = []
    for q in queries:
        digest = hashlib.sha1(q.encode()).hexdigest()[:10]
        name = f'mv_auto_{digest}'
        create_sql = f'CREATE MATERIALIZED VIEW IF NOT EXISTS {schema}.{name} AS {q};'
        refresh_sql = f'ReFRESH MATERIALIZED VIEW CONCURRENTLY {schema}.{name};'
        mvs.append(MaterializedView(name=name, create_sql=create_sql, refresh_sql=refresh_sql))
    return mvs


def visualize_plan(plan: Dict[str, Any], out_path: Path) -> Path:
    """Render a JSON EXPLAIN plan to a DOT/PNG using graphviz if available."""
    try:
        import graphviz
    except Exception:
        raise RuntimeError('graphviz python package is required for visualization')

    dot = graphviz.Digraph(comment='Query Plan')

    def walk(node: Dict[str, Any], parent: Optional[str] = None, idx: int = 0):
        nid = f"{id(node)}_{idx}"
        label = node.get('Node Type', 'Node')
        label += '\n' + json.dumps({k: v for k, v in node.items() if k in ('Actual Rows', 'Actual Total Time', 'Plan Rows')}, default=str)
        dot.node(nid, label)
        if parent:
            dot.edge(parent, nid)
        for i, child in enumerate(node.get('Plans', []) if node.get('Plans') else []):
            walk(child, nid, i)

    # Plan root may be a list
    root = plan if isinstance(plan, dict) else (plan[0] if isinstance(plan, list) and plan else plan)
    walk(root)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    dot.render(str(out_path), format='png', cleanup=True)
    return out_path.with_suffix('.png')


if __name__ == '__main__':
    # Simple CLI for local analysis
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument('--analyze', action='store_true')
    ap.add_argument('--threshold', type=int, default=100)
    args = ap.parse_args()
    if args.analyze:
        sq = analyze_slow_queries(threshold_ms=args.threshold)
        for s in sq:
            print(f'{s.mean_ms}ms calls={s.calls}\n{s.query[:200]}\n')

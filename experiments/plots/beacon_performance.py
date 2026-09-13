"""Plot throughput and amortized latency from selected beacon run-results.csv files."""

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from statistics import fmean

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

COLORS = {"silk-beacon": "#56B4E9", "rondo-beacon": "#F0A44B", "spurt-beacon": "#009E73"}


def load_results(paths):
    groups = defaultdict(list)
    seen = set()
    for path in paths:
        validation = json.loads(path.with_name("node-validation.json").read_text(encoding="utf-8"))
        if not validation["run_valid"]:
            raise ValueError(f"Invalid run: {path}")
        with path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        if len(rows) != 1:
            raise ValueError(f"Expected one run in {path}")
        row = rows[0]
        if row["run_id"] in seen:
            raise ValueError(f"Duplicate run: {row['run_id']}")
        seen.add(row["run_id"])
        n = int(row["expected_node_count"])
        if n != int(row["valid_node_count"]) or row["run_id"] != validation["run_id"]:
            raise ValueError(f"Incomplete or mismatched run: {path}")
        outputs = int(row["output_count"])
        wall = int(row["measurement_wall_ns"]) / 1e9
        throughput = float(row["throughput_outputs_per_second"])
        wire = float(row["wire_bytes_per_output"])
        if outputs <= 0 or wall <= 0 or not all(math.isfinite(v) and v >= 0 for v in (throughput, wire)):
            raise ValueError(f"Invalid measurements: {path}")
        groups[n, row["implementation"]].append({
            "throughput": throughput,
            "latency": wall / outputs,
            "bandwidth": wire / n / 2**20,
        })
    if not groups:
        raise ValueError("No results selected")
    return {key: {metric: fmean(row[metric] for row in rows) for metric in rows[0]}
            for key, rows in groups.items()}


def draw(ax, results, metric, ylabel):
    for protocol in sorted({protocol for _, protocol in results}):
        sizes = sorted(n for n, name in results if name == protocol)
        ax.plot(sizes, [results[n, protocol][metric] for n in sizes], marker="o",
                label=protocol.removesuffix("-beacon").capitalize(), color=COLORS.get(protocol))
    ax.set(xlabel="Committee size", ylabel=ylabel)
    ax.set_xticks(sorted({n for n, _ in results}))
    ax.set_ylim(bottom=0)
    ax.grid(axis="y", alpha=0.2)
    ax.legend(frameon=False)


def arguments(description, filename):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("results", type=Path, nargs="+", help="Comparable run-results.csv files")
    parser.add_argument("--output", type=Path, default=Path("output/figures") / filename)
    return parser.parse_args()


def main():
    args = arguments(__doc__, "beacon-performance.png")
    results = load_results(args.results)
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.5), layout="constrained")
    draw(axes[0], results, "throughput", "Throughput (outputs/s)")
    draw(axes[1], results, "latency", "Amortized latency (s/output)")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, dpi=200)
    plt.close(fig)


if __name__ == "__main__":
    main()

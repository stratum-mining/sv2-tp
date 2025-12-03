#!/usr/bin/env python3
"""Plot GetTemplateMemoryUsage durations and template memory footprints over time."""
from __future__ import annotations

import argparse
import datetime as dt
import pickle
import re
from pathlib import Path
from typing import List, Tuple

import matplotlib.dates as mdates  # type: ignore[import, import-not-found]
import matplotlib.pyplot as plt  # type: ignore[import, import-not-found]
from matplotlib import transforms  # type: ignore[import, import-not-found]
from matplotlib.ticker import NullFormatter  # type: ignore[import, import-not-found]

MEMORY_LOAD_COMPLETED = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z).*GetTemplateMemoryUsage:.*completed \((?P<ms>\d+\.\d+)ms\)"
)
UPDATE_TIP = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z).*UpdateTip:.*height=(?P<height>\d+) "
)
TP_LOG_ENTRY = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)Z.*Template memory footprint (?P<mib>\d+(?:\.\d+)?) MiB"
)

TIP_LABEL_MIN_FRACTION = 0.02
CLIPPED_LABEL_MIN_FRACTION = 0.01
DEFAULT_DURATION_CAP_MS = 15.0  # Hard cap for GetTemplateMemoryUsage durations


def format_with_machine(base: str, machine: str | None) -> str:
    return f"{base} ({machine})" if machine else base


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "bitcoin_log",
        type=Path,
        help="Path to bitcoin debug log containing GetTemplateMemoryUsage entries",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("getmemoryload-scatter.svg"),
        help="Destination image path (default: ./getmemoryload-scatter.svg)",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Display the plot interactively instead of saving it",
    )
    parser.add_argument(
        "tp_log",
        type=Path,
        help="SV2 template provider log containing 'Template memory footprint' lines",
    )
    parser.add_argument(
        "--since",
        type=str,
        default=None,
        help=(
            "Ignore log events earlier than this ISO 8601 timestamp. Naive timestamps "
            "are interpreted as UTC (e.g. '2025-12-02T14:50:00')."
        ),
    )
    parser.add_argument(
        "--duration-cap",
        type=float,
        default=DEFAULT_DURATION_CAP_MS,
        help=(
            "Clip GetTemplateMemoryUsage durations above this value (ms) and annotate their "
            f"true value at the top of the chart. Default: {DEFAULT_DURATION_CAP_MS:.0f} ms."
        ),
    )
    parser.add_argument(
        "--figure-pickle",
        type=Path,
        default=None,
        help=(
            "Optional path to write a pickle of the Matplotlib Figure for further "
            "inspection."
        ),
    )
    parser.add_argument(
        "--dpi",
        type=int,
        default=300,
        help="Raster output resolution (applies to PNG/JPEG/TIFF). Default: 300 dpi.",
    )
    parser.add_argument(
        "--machine",
        type=str,
        default=None,
        help="Optional machine label to append to dataset names (e.g. 'M4').",
    )
    return parser.parse_args()


def parse_timestamp(raw: str) -> dt.datetime:
    """Return timezone-aware UTC timestamps from log entries."""
    parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def parse_since_timestamp(raw: str) -> dt.datetime:
    sanitized = raw.strip()
    if not sanitized:
        raise SystemExit("--since timestamp must not be empty")
    if sanitized.endswith("Z"):
        sanitized = f"{sanitized[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(sanitized)
    except ValueError as exc:
        raise SystemExit(f"Invalid --since timestamp '{raw}': {exc}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def load_events(log_path: Path, since: dt.datetime | None = None):
    mem_points = []
    tip_events = []
    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            mem_match = MEMORY_LOAD_COMPLETED.search(line)
            if mem_match:
                timestamp = parse_timestamp(mem_match.group("ts"))
                if since is not None and timestamp < since:
                    continue
                mem_points.append((timestamp, float(mem_match.group("ms"))))
                continue
            tip_match = UPDATE_TIP.search(line)
            if tip_match:
                timestamp = parse_timestamp(tip_match.group("ts"))
                if since is not None and timestamp < since:
                    continue
                tip_events.append((timestamp, int(tip_match.group("height"))))
    mem_points.sort(key=lambda item: item[0])
    tip_events.sort(key=lambda item: item[0])
    return mem_points, tip_events


def load_tp_points(
    log_path: Path, since: dt.datetime | None = None
) -> List[Tuple[dt.datetime, float]]:
    tp_points: List[Tuple[dt.datetime, float]] = []
    if not log_path.exists():
        raise SystemExit(f"Template provider log '{log_path}' not found")

    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            match = TP_LOG_ENTRY.search(line)
            if match:
                mib_val = float(match.group("mib"))
                timestamp = parse_timestamp(match.group("ts"))
                if since is not None and timestamp < since:
                    continue
                tp_points.append((timestamp, mib_val))

    tp_points.sort(key=lambda item: item[0])
    if not tp_points:
        raise SystemExit(
            f"No template provider entries were found in '{log_path}'. Does it contain "
            "'Template memory footprint' lines?"
        )
    return tp_points

def plot_memory_load(
    mem_points,
    tip_events,
    tp_points,
    duration_cap,
    figure_pickle: Path | None,
    dpi: int,
    machine_label: str | None,
    output: Path,
    show_plot: bool,
) -> None:
    if not mem_points:
        raise SystemExit("No GetTemplateMemoryUsage() completion records found in log")

    times, durations = zip(*mem_points)
    fig, ax = plt.subplots(figsize=(15, 5))
    fig.patch.set_facecolor("white")
    fig.patch.set_alpha(1.0)
    ax.set_facecolor("white")
    duration_label = format_with_machine("GetTemplateMemoryUsage() duration", machine_label)
    ax.scatter(
        times,
        durations,
        s=5,
        color="tab:blue",
        label=duration_label,
        zorder=3,
    )

    ax.set_ylabel("Duration (ms)")
    ax.set_xlabel("")
    ax.set_title("")
    ax.xaxis.set_major_formatter(NullFormatter())
    ax.margins(x=0)

    max_duration = max(durations)
    effective_cap = duration_cap
    clipped_points = []
    if effective_cap is not None and effective_cap < max_duration:
        ax.set_ylim(bottom=0, top=effective_cap)
        clipped_points = [(timestamp, value) for timestamp, value in mem_points if value > effective_cap]
    else:
        upper_pad = max_duration * 1.05 if max_duration > 0 else 1
        ax.set_ylim(bottom=0, top=upper_pad)

    twin_ax = None
    if tp_points:
        tp_times, tp_mib = zip(*tp_points)
        twin_ax = ax.twinx()
        twin_ax.margins(x=0)
        twin_ax.vlines(
            tp_times,
            [0] * len(tp_times),
            tp_mib,
            color="#4fbf73",
            alpha=0.5,
            linewidth=1,
            zorder=1,
            label="Template provider memory",
        )
        twin_ax.set_ylabel("Memory footprint (MiB)", color="#2b8a46")
        twin_ax.tick_params(axis="y", colors="#2b8a46")
        twin_ax.set_ylim(bottom=0)

    if clipped_points:
        clip_trans = transforms.blended_transform_factory(ax.transData, ax.transAxes)
        marker_y = 1.0
        clipped_times = [timestamp for timestamp, _ in clipped_points]
        clipped_values = [value for _, value in clipped_points]
        clipped_time_nums = mdates.date2num(clipped_times)
        ax.scatter(
            clipped_time_nums,
            [marker_y] * len(clipped_points),
            marker="o",
            s=22,
            facecolors="none",
            edgecolors="tab:blue",
            linewidths=1,
            label=f"Clipped duration (> {effective_cap:.2f} ms)",
            transform=clip_trans,
            clip_on=False,
            zorder=4,
        )
        label_min_delta = (ax.get_xlim()[1] - ax.get_xlim()[0]) * CLIPPED_LABEL_MIN_FRACTION
        last_clipped_label_num: float | None = None
        for ts_num, value in zip(clipped_time_nums, clipped_values):
            if last_clipped_label_num is not None and ts_num - last_clipped_label_num < label_min_delta:
                continue
            label = f"{value:.0f} ms"
            ax.annotate(
                label,
                xy=(ts_num, marker_y),
                xycoords=clip_trans,
                xytext=(0, -8),
                textcoords="offset points",
                ha="center",
                va="top",
                fontsize=8,
                color="tab:blue",
                rotation=270,
                clip_on=False,
            )
            last_clipped_label_num = ts_num

    if tip_events:
        tip_color = "tab:red"
        tip_times, tip_heights = zip(*tip_events)
        tip_time_nums = mdates.date2num(tip_times)
        trans = transforms.blended_transform_factory(ax.transData, ax.transAxes)
        marker_y = -0.01
        ax.scatter(
            tip_time_nums,
            [marker_y] * len(tip_events),
            marker="^",
            s=70,
            color=tip_color,
            edgecolors="none",
            label="Tip update",
            zorder=4,
            transform=trans,
            clip_on=False,
        )
        label_trans = transforms.blended_transform_factory(ax.transData, ax.transAxes)
        x_start, x_end = ax.get_xlim()
        min_delta = (x_end - x_start) * TIP_LABEL_MIN_FRACTION
        last_label_num: float | None = None
        for ts_num, height in zip(tip_time_nums, tip_heights):
            if last_label_num is not None and ts_num - last_label_num < min_delta:
                continue
            label = f"{height:,}"
            ax.annotate(
                label,
                xy=(ts_num, 0),
                xycoords=label_trans,
                xytext=(1, -8),
                textcoords="offset points",
                rotation=45,
                ha="right",
                va="top",
                color=tip_color,
                fontsize=8,
                clip_on=False,
            )
            last_label_num = ts_num

    handles, labels = ax.get_legend_handles_labels()
    if twin_ax is not None:
        twin_handles, twin_labels = twin_ax.get_legend_handles_labels()
        handles += twin_handles
        labels += twin_labels
    try:
        tip_idx = labels.index("Tip update")
        tip_handle = handles.pop(tip_idx)
        tip_label = labels.pop(tip_idx)
        handles.append(tip_handle)
        labels.append(tip_label)
    except ValueError:
        pass
    legend = fig.legend(
        handles,
        labels,
        loc="upper left",
        bbox_to_anchor=(0.12, 0.78),
    )
    legend.set_zorder(10)
    frame = legend.get_frame()
    frame.set_alpha(0.75)
    frame.set_zorder(legend.get_zorder())
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)

    if figure_pickle is not None:
        figure_pickle.parent.mkdir(parents=True, exist_ok=True)
        with figure_pickle.open("wb") as handle:
            pickle.dump(fig, handle)

    if show_plot:
        plt.show()
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        raster_exts = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif"}
        if output.suffix.lower() in raster_exts:
            fig.savefig(output, bbox_inches="tight", facecolor=fig.get_facecolor(), dpi=dpi)
        else:
            fig.savefig(output, bbox_inches="tight", facecolor=fig.get_facecolor())
        print(f"Wrote {output}")

    plt.close(fig)


def main() -> None:
    args = parse_args()
    since_ts = parse_since_timestamp(args.since) if args.since else None
    mem_points, tip_events = load_events(args.bitcoin_log, since_ts)
    tp_points = load_tp_points(args.tp_log, since_ts)
    plot_memory_load(
        mem_points,
        tip_events,
        tp_points,
        args.duration_cap,
        args.figure_pickle,
        args.dpi,
        args.machine,
        args.output,
        args.show,
    )


if __name__ == "__main__":
    main()

import argparse
import sys
from pathlib import Path

from .constants import (
    ALL_COLUMNS,
    DEFAULT_HOST_WINDOW_SECONDS,
    DEFAULT_LLM_MAX_NEW_TOKENS,
    DEFAULT_LLM_MODEL_NAME,
    DEFAULT_OTHER_TIMEOUT,
    DEFAULT_PARTIAL_PACKET_STEPS,
    DEFAULT_PARTIAL_TIME_STEPS,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_TCP_TIMEOUT,
    DEFAULT_UDP_TIMEOUT,
    IDENTITY_COLUMNS,
    PROFILE_COLUMNS,
)
from .models import LLMContextConfig, PartialExportConfig, UserLabelConfig
from .utils import parse_packet_steps, parse_time_steps


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="EV-IDS Sentinel transforms Electric Vehicle PCAP traffic into IDS-style CSV flow features in offline or live mode."
    )
    parser.add_argument(
        "--mode",
        choices=["offline", "live"],
        default="offline",
        help="Extraction mode: offline reads a PCAP file, live sniffs an interface.",
    )
    parser.add_argument("--input", help="Input PCAP or PCAPNG file path for offline mode")
    parser.add_argument("--interface", help="Network interface name for live mode")
    parser.add_argument("--output", required=True, help="Output CSV file path")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILE_COLUMNS),
        default="full",
        help="Output profile controlling which columns are written.",
    )
    parser.add_argument(
        "--binary-label",
        default="",
        help="User-supplied binary label written to every exported row, for example benign or attack.",
    )
    parser.add_argument(
        "--multiclass-label",
        default="",
        help="User-supplied EV multiclass label written to every exported row, for example benign, AFS_DoS, GPS_Injection, or SIP_Flood.",
    )
    parser.add_argument(
        "--enable-llm-context",
        action="store_true",
        help="Generate a new llm_context column by sending each exported feature row to a local Qwen model through Transformers.",
    )
    parser.add_argument(
        "--llm-model-name",
        default=DEFAULT_LLM_MODEL_NAME,
        help=f"Transformers model name or local path used for llm_context generation (default: {DEFAULT_LLM_MODEL_NAME}).",
    )
    parser.add_argument(
        "--llm-max-new-tokens",
        type=int,
        default=DEFAULT_LLM_MAX_NEW_TOKENS,
        help=f"Maximum tokens generated for each llm_context value (default: {DEFAULT_LLM_MAX_NEW_TOKENS}).",
    )
    parser.add_argument(
        "--tcp-timeout",
        type=float,
        default=DEFAULT_TCP_TIMEOUT,
        help=f"Inactivity timeout for TCP flows in seconds (default: {DEFAULT_TCP_TIMEOUT})",
    )
    parser.add_argument(
        "--udp-timeout",
        type=float,
        default=DEFAULT_UDP_TIMEOUT,
        help=f"Inactivity timeout for UDP flows in seconds (default: {DEFAULT_UDP_TIMEOUT})",
    )
    parser.add_argument(
        "--other-timeout",
        type=float,
        default=DEFAULT_OTHER_TIMEOUT,
        help=f"Inactivity timeout for non-TCP/UDP flows in seconds (default: {DEFAULT_OTHER_TIMEOUT})",
    )
    parser.add_argument(
        "--host-window-seconds",
        type=float,
        default=DEFAULT_HOST_WINDOW_SECONDS,
        help=f"Rolling host-behavior window in seconds (default: {DEFAULT_HOST_WINDOW_SECONDS})",
    )
    parser.add_argument(
        "--enable-partial",
        action="store_true",
        help="Emit partial-flow snapshots at packet and time milestones.",
    )
    parser.add_argument(
        "--partial-packet-steps",
        default=",".join(str(x) for x in DEFAULT_PARTIAL_PACKET_STEPS),
        help="Comma-separated packet milestones for partial snapshots.",
    )
    parser.add_argument(
        "--partial-time-steps",
        default=",".join(str(x) for x in DEFAULT_PARTIAL_TIME_STEPS),
        help="Comma-separated duration milestones in seconds for partial snapshots.",
    )
    parser.add_argument(
        "--baseline-csv",
        help="Optional baseline feature CSV used to generate a drift report after extraction.",
    )
    parser.add_argument(
        "--report-prefix",
        help="Optional path prefix used for generated drift and consistency reports.",
    )
    parser.add_argument(
        "--bpf-filter",
        default="",
        help="Optional live-capture BPF filter, for example 'tcp or udp'.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Maximum live-capture duration in seconds. Use 0 for unlimited capture.",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=0,
        help="Maximum number of live packets to process. Use 0 for unlimited capture.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help="Live mode polling interval in seconds for flow expiry and CSV export.",
    )
    parser.add_argument(
        "--no-promisc",
        action="store_true",
        help="Disable promiscuous mode during live capture.",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    output_path = Path(args.output)
    input_path = Path(args.input) if args.input else None
    baseline_csv = Path(args.baseline_csv) if args.baseline_csv else None
    report_prefix = Path(args.report_prefix) if args.report_prefix else None

    if args.mode == "offline":
        if input_path is None:
            print("Offline mode requires --input", file=sys.stderr)
            return 1
        if not input_path.exists():
            print(f"Input file not found: {input_path}", file=sys.stderr)
            return 1

    if args.mode == "live" and not args.interface:
        print("Live mode requires --interface", file=sys.stderr)
        return 1

    if baseline_csv is not None and not baseline_csv.exists():
        print(f"Baseline CSV not found: {baseline_csv}", file=sys.stderr)
        return 1

    partial_config = PartialExportConfig(
        enabled=bool(args.enable_partial),
        packet_steps=parse_packet_steps(args.partial_packet_steps),
        time_steps=parse_time_steps(args.partial_time_steps),
    )
    label_config = UserLabelConfig(
        binary_label=args.binary_label,
        multiclass_label=args.multiclass_label,
    )
    llm_config = LLMContextConfig(
        enabled=bool(args.enable_llm_context),
        model_name=args.llm_model_name,
        max_new_tokens=args.llm_max_new_tokens,
    )

    try:
        from .pipeline import run_extractor

        summary = run_extractor(
            mode=args.mode,
            input_path=input_path,
            interface=args.interface,
            output_path=output_path,
            tcp_timeout=args.tcp_timeout,
            udp_timeout=args.udp_timeout,
            other_timeout=args.other_timeout,
            bpf_filter=args.bpf_filter,
            duration=args.duration,
            max_packets=args.max_packets,
            poll_interval=args.poll_interval,
            promiscuous=not args.no_promisc,
            profile=args.profile,
            partial_config=partial_config,
            host_window_seconds=args.host_window_seconds,
            baseline_csv=baseline_csv,
            report_prefix=report_prefix,
            label_config=label_config,
            llm_config=llm_config,
        )
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Mode: {summary['mode']}")
    print(f"Wrote {summary['row_count']} rows to {summary['output_path']}")
    print(f"Output profile: {args.profile}")
    print(f"Feature columns available in full schema: {len(ALL_COLUMNS) - len(IDENTITY_COLUMNS)}")
    print(f"Total full-schema columns: {len(ALL_COLUMNS)}")
    print(
        "User labels: "
        f"binary='{label_config.binary_label.strip()}', multiclass='{label_config.multiclass_label.strip()}'"
    )
    print(
        "LLM context: "
        f"enabled={llm_config.enabled}, model='{llm_config.model_name}', max_new_tokens={llm_config.max_new_tokens}"
    )
    if summary.get("drift_csv"):
        print(f"Drift CSV: {summary['drift_csv']}")
    if summary.get("drift_md"):
        print(f"Drift report: {summary['drift_md']}")
    if summary.get("consistency_csv"):
        print(f"Consistency CSV: {summary['consistency_csv']}")
    if summary.get("consistency_md"):
        print(f"Consistency report: {summary['consistency_md']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

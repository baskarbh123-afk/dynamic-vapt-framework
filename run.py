#!/usr/bin/env python3
"""
Autonomous AI Pentesting Platform — Main Entry Point
=====================================================
Launches the AI Orchestrator to coordinate multi-agent penetration testing.

Usage:
  python3 run.py                              # Run all phases
  python3 run.py --phase recon                # Run recon only
  python3 run.py --phase recon,enumeration    # Run specific phases
  python3 run.py --status                     # Show system status
  python3 run.py --tools                      # List available tools
  python3 run.py --dry-run                    # Plan only, don't execute
  python3 run.py --config engagement.yaml     # Use specific config
  python3 run.py --graph                      # Show asset graph statistics
  python3 run.py --chains                     # Run attack chain analysis
  python3 run.py --bug-bounty                 # Enable bug bounty mode
  python3 run.py --report-html                # Generate HTML report
  python3 run.py --monitor                    # Start continuous monitoring
"""

import json
import logging
import sys
from pathlib import Path

# Ensure project root is on path
ROOT = Path(__file__).parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.orchestrator import main, setup_logging, Orchestrator


def extended_main():
    """Extended CLI with v2 architecture commands."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Autonomous AI Pentesting Platform v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", help="Path to config file (default: config.yaml)")
    parser.add_argument("--phase", help="Run specific phase(s), comma-separated")
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument("--tools", action="store_true", help="List available tools")
    parser.add_argument("--summary", action="store_true", help="Show knowledge base summary")
    parser.add_argument("--dry-run", action="store_true", help="Plan only, don't execute")
    parser.add_argument("--log-level", default="INFO", help="Log level (DEBUG/INFO/WARNING/ERROR)")

    # v2 commands
    parser.add_argument("--graph", action="store_true", help="Show asset graph statistics")
    parser.add_argument("--chains", action="store_true", help="Run attack chain detection")
    parser.add_argument("--bug-bounty", action="store_true", help="Activate bug bounty hunter mode")
    parser.add_argument("--report-html", action="store_true", help="Generate HTML report from current findings")
    parser.add_argument("--monitor", action="store_true", help="Start continuous surface monitoring")
    parser.add_argument("--recon-full", action="store_true", help="Run full 7-stage recon pipeline (stages 4-7)")

    args = parser.parse_args()
    setup_logging(args.log_level)
    logger = logging.getLogger("run")

    # Handle v2-only commands
    if any([args.graph, args.chains, args.report_html, args.monitor, args.recon_full, args.bug_bounty]):
        try:
            orch = Orchestrator(config_path=args.config)
            orch.load_config()
            orch.initialize()

            if args.graph:
                if getattr(orch, "graph", None):
                    orch._graph_sync.sync_all()
                    stats = orch.graph.stats()
                    print("\nAsset Graph Statistics:")
                    print(json.dumps(stats, indent=2))
                else:
                    print("Graph DB not available (v2 components not initialized)")
                return

            if args.chains:
                if getattr(orch, "chain_engine", None):
                    vulns = orch.kb.get_vulnerabilities(status="POC_VERIFIED")
                    if not vulns:
                        vulns = orch.kb.get_all("vulnerabilities")
                    chains = orch.chain_engine.detect(vulns)
                    orch.chain_engine.save()
                    print(f"\nAttack Chain Analysis — {len(chains)} chain(s) detected:")
                    for chain in chains:
                        print(f"  [{chain.template.severity.upper()}] {chain.template.chain_id}: "
                              f"{chain.template.name} (score={chain.chain_score}/10)")
                else:
                    print("Attack chain engine not available")
                return

            if args.report_html:
                try:
                    from core.report_engine import ReportEngine
                    engine = ReportEngine(orch.config)
                    findings = orch.kb.get_all("vulnerabilities")
                    chains = orch.kb.get_all("attack_paths")
                    paths = engine.generate_all(findings, chains)
                    print(f"\nReports generated:")
                    for fmt, path in paths.items():
                        print(f"  {fmt}: {path}")
                except ImportError:
                    print("Report engine not available")
                return

            if args.bug_bounty:
                try:
                    from modes.bug_bounty_mode import BugBountyMode
                    bb = BugBountyMode(orch.config)
                    overrides = bb.get_scan_config_overrides()
                    print("\nBug Bounty Mode Configuration:")
                    print(json.dumps(overrides, indent=2))
                    print(f"\nProgram: {bb.bb_config.program_name} on {bb.bb_config.platform}")
                    print(f"Priority vulns: {', '.join(bb.bb_config.priority_vuln_types[:5])}")
                    print(f"Monitoring: every {bb.bb_config.monitor_interval_hours}h")
                except ImportError:
                    print("Bug bounty mode not available")
                return

            if args.recon_full:
                if getattr(orch, "recon_pipeline", None):
                    target = orch.config.get("target", {}).get("domain", "")
                    live_hosts = [
                        ep.get("url", "") for ep in orch.kb.get_all("endpoints")
                        if ep.get("url", "").startswith("http")
                    ]
                    if not live_hosts and target:
                        live_hosts = [f"https://{target}"]
                    result = orch.recon_pipeline.run_stages_4_to_7(target, live_hosts)
                    print(f"\nRecon Pipeline (Stages 4-7) complete for {target}:")
                    print(f"  Historical URLs:  {len(result.historical_urls)}")
                    print(f"  Crawled URLs:     {len(result.crawled_urls)}")
                    print(f"  JS Endpoints:     {len(result.js_endpoints)}")
                    print(f"  JS Sinks found:   {len(result.js_sinks)}")
                    print(f"  Secrets detected: {len(result.js_secrets)}")
                    print(f"  Parameters:       {len(result.parameters)} endpoints")
                    print(f"  API Schemas:      {len(result.api_schemas)}")
                    if result.js_secrets:
                        print(f"\n  [!] SECRET PATTERNS detected — review evidence/js_secrets/")
                else:
                    print("Recon pipeline not available")
                return

            if args.monitor:
                print("Continuous monitoring requires an async runtime.")
                print("Run: python3 -c \"import asyncio; from core.continuous_monitor import *; asyncio.run(...)\"")
                print("See core/continuous_monitor.py for usage.")
                return

        except Exception as e:
            logger.error(f"v2 command failed: {e}", exc_info=True)
            sys.exit(1)
    else:
        # Fall through to standard orchestrator main
        main()


if __name__ == "__main__":
    extended_main()

#!/usr/bin/env python3
"""
AI Orchestrator — Central Coordinator for VAPT Framework
==========================================================
Coordinates the full penetration testing lifecycle:

  1. Load Configuration (engagement.yaml / config.yaml)
  2. Initialize System (KB, Tools, Agents)
  3. Reconnaissance Phase
  4. Enumeration Phase
  5. Vulnerability Discovery Phase
  6. Exploitation Phase
  7. Attack Chain Analysis
  8. Report Generation
  9. Email Notification System
  10. Logging

All phase results flow through the Knowledge Base.
"""

import json
import logging
import sys
import os
from datetime import datetime
from pathlib import Path

import yaml

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).parent.parent.resolve()
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.knowledge_base import KnowledgeBase
from core.tool_integrations import ToolIntegrations
from agents.recon_agent import ReconAgent
from agents.enumeration_agent import EnumerationAgent
from agents.vulnerability_agent import VulnerabilityAgent
from agents.poc_agent import PoCAgent
from agents.exploit_agent import ExploitAgent
from agents.attack_chain_agent import AttackChainAgent
from agents.report_agent import ReportAgent
from agents.notification_agent import NotificationAgent
from typing import Any, Dict, List, Optional

LOG_DIR = BASE_DIR / "logs"
ENGAGEMENT_LOG = LOG_DIR / "engagement.log"

logger = logging.getLogger("orchestrator")


class Orchestrator:
    """Central coordinator for the multi-agent VAPT system."""

    AGENT_CLASSES = [
        ReconAgent,
        EnumerationAgent,
        VulnerabilityAgent,
        PoCAgent,
        ExploitAgent,
        AttackChainAgent,
        ReportAgent,
        NotificationAgent,
    ]

    PHASE_ORDER = [
        "recon",
        "enumeration",
        "vulnerability",
        "poc_validation",
        "exploit",
        "attack_chain",
        "report",
        "notification",
    ]

    def __init__(self, config_path: Optional[str] = None):
        self.config: dict = {}
        self.kb: Optional[KnowledgeBase] = None
        self.tools: Optional[ToolIntegrations] = None
        self.agents: Dict[str, object] = {}
        self.phase_results: Dict[str, dict] = {}
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None

        # Resolve config path
        if config_path:
            self.config_path = Path(config_path)
        else:
            # Try engagement.yaml first, fall back to config.yaml
            engagement_yaml = BASE_DIR / "engagement.yaml"
            config_yaml = BASE_DIR / "config.yaml"
            if engagement_yaml.exists():
                self.config_path = engagement_yaml
            elif config_yaml.exists():
                self.config_path = config_yaml
            else:
                raise FileNotFoundError("No engagement.yaml or config.yaml found")

    # ------------------------------------------------------------------
    # Step 1: Load Configuration
    # ------------------------------------------------------------------
    def load_config(self) -> dict:
        """Load engagement configuration."""
        logger.info(f"Loading configuration from {self.config_path}")
        with open(self.config_path) as f:
            self.config = yaml.safe_load(f)

        if not self.config:
            raise ValueError(f"Configuration file is empty: {self.config_path}")

        # Validate critical fields
        eng = self.config.get("engagement", {})
        auth = self.config.get("authorization", {})

        if not auth.get("roe_signed"):
            raise ValueError("authorization.roe_signed must be true — cannot proceed without authorization")

        logger.info(f"Configuration loaded: {eng.get('name', 'N/A')} ({eng.get('id', 'N/A')})")
        return self.config

    # ------------------------------------------------------------------
    # Step 2: Initialize System
    # ------------------------------------------------------------------
    def initialize(self):
        """Initialize Knowledge Base, Tool Integrations, and Agents."""
        logger.info("Initializing system...")

        # Knowledge Base
        self.kb = KnowledgeBase()
        logger.info("Knowledge Base initialized")

        # Tool Integrations
        self.tools = ToolIntegrations(self.config)
        available = self.tools.available()
        logger.info(f"Tool Integrations initialized — {len(available)} tools available")

        # Initialize Agents
        for agent_cls in self.AGENT_CLASSES:
            agent = agent_cls(self.config, self.kb, self.tools)
            self.agents[agent.phase] = agent
            logger.info(f"Agent initialized: {agent.name} (phase: {agent.phase})")

        logger.info(f"System initialized with {len(self.agents)} agents")

    # ------------------------------------------------------------------
    # Phase Execution
    # ------------------------------------------------------------------
    def run_phase(self, phase: str) -> dict:
        """Run a single phase by name."""
        agent = self.agents.get(phase)
        if not agent:
            raise ValueError(f"No agent for phase '{phase}'. Available: {list(self.agents.keys())}")

        logger.info(f"\n{'='*60}")
        logger.info(f"PHASE: {phase.upper()}")
        logger.info(f"Agent: {agent.name}")
        logger.info(f"{'='*60}")

        result = agent.run()
        self.phase_results[phase] = result

        logger.info(f"Phase {phase} complete: {json.dumps(result, indent=2, default=str)[:500]}")
        return result

    def run_all(self, phases: Optional[List[str]] = None) -> dict:
        """Run all phases in order (or a subset)."""
        self.started_at = datetime.now().isoformat()
        phases_to_run = phases or self.PHASE_ORDER

        # Check which phases are enabled in config
        phase_config = self.config.get("preferences", {}).get("phases_to_run", {})
        phase_map = {
            "recon": "recon",
            "enumeration": "enumeration",
            "vulnerability": "exploitation",
            "poc_validation": "exploitation",
            "exploit": "exploitation",
            "attack_chain": "post_exploitation",
            "report": "reporting",
            "notification": "reporting",
        }

        results = {}
        for phase in phases_to_run:
            config_key = phase_map.get(phase, phase)
            if not phase_config.get(config_key, True):
                logger.info(f"Phase '{phase}' is disabled in config — skipping")
                continue

            try:
                result = self.run_phase(phase)
                results[phase] = result
            except Exception as e:
                logger.error(f"Phase '{phase}' failed: {e}")
                results[phase] = {"status": "failed", "error": str(e)}

        self.completed_at = datetime.now().isoformat()

        # Final summary
        summary = {
            "engagement": self.config.get("engagement", {}).get("id", ""),
            "started": self.started_at,
            "completed": self.completed_at,
            "phases_run": list(results.keys()),
            "kb_summary": self.kb.summary() if self.kb else {},
            "phase_results": results,
        }

        self._save_execution_log(summary)
        return summary

    # ------------------------------------------------------------------
    # Status & Reporting
    # ------------------------------------------------------------------
    def status(self) -> dict:
        """Get current system status."""
        agent_statuses = {}
        for phase, agent in self.agents.items():
            agent_statuses[phase] = agent.status()

        return {
            "engagement": self.config.get("engagement", {}).get("name", "N/A"),
            "config": str(self.config_path),
            "kb_summary": self.kb.summary() if self.kb else {},
            "tools_available": len(self.tools.available()) if self.tools else 0,
            "agents": agent_statuses,
            "phases_completed": list(self.phase_results.keys()),
        }

    def _save_execution_log(self, summary: dict):
        """Save execution summary to logs."""
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        # Save JSON log
        log_file = LOG_DIR / "orchestrator_execution.json"
        with open(log_file, "w") as f:
            json.dump(summary, f, indent=2, default=str)

        # Append to engagement log
        with open(ENGAGEMENT_LOG, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"[{datetime.now().isoformat()}] Orchestrator Execution Complete\n")
            f.write(f"Phases run: {', '.join(summary.get('phases_run', []))}\n")
            kb = summary.get("kb_summary", {})
            f.write(f"Assets: {kb.get('assets', 0)} | "
                    f"Endpoints: {kb.get('endpoints', 0)} | "
                    f"Vulnerabilities: {kb.get('vulnerabilities', 0)} | "
                    f"Evidence: {kb.get('evidence', 0)} | "
                    f"Attack Paths: {kb.get('attack_paths', 0)}\n")
            f.write(f"{'='*60}\n")

        logger.info(f"Execution log saved to {log_file}")


# ============================================================================
# Logging Setup
# ============================================================================
def setup_logging(level: str = "INFO"):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear existing handlers
    root_logger.handlers = []

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(log_level)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S"
    ))
    root_logger.addHandler(console)

    # File handler
    file_handler = logging.FileHandler(LOG_DIR / "agent_execution.log")
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    ))
    root_logger.addHandler(file_handler)


# ============================================================================
# CLI Entry Point
# ============================================================================
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="VAPT Framework — AI Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 core/orchestrator.py                          # Run all phases
  python3 core/orchestrator.py --phase recon            # Run recon only
  python3 core/orchestrator.py --phase recon,enumeration # Run specific phases
  python3 core/orchestrator.py --status                 # Show system status
  python3 core/orchestrator.py --tools                  # List available tools
  python3 core/orchestrator.py --config engagement.yaml # Use specific config
        """
    )
    parser.add_argument("--config", help="Path to engagement config (default: engagement.yaml or config.yaml)")
    parser.add_argument("--phase", help="Run specific phase(s), comma-separated")
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument("--tools", action="store_true", help="List available tools")
    parser.add_argument("--summary", action="store_true", help="Show knowledge base summary")
    parser.add_argument("--log-level", default="INFO", help="Log level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--dry-run", action="store_true", help="Plan only, don't execute")

    args = parser.parse_args()
    setup_logging(args.log_level)

    try:
        orch = Orchestrator(config_path=args.config)
        orch.load_config()
        orch.initialize()

        if args.tools:
            tools = orch.tools.available()
            print(f"\nAvailable Tools ({len(tools)}):")
            for name, path in sorted(tools.items()):
                print(f"  {name:<25} {path}")
            return

        if args.status:
            status = orch.status()
            print(json.dumps(status, indent=2, default=str))
            return

        if args.summary:
            summary = orch.kb.summary()
            print(json.dumps(summary, indent=2))
            return

        if args.dry_run:
            for phase_name in (args.phase.split(",") if args.phase else orch.PHASE_ORDER):
                agent = orch.agents.get(phase_name.strip())
                if agent:
                    plan = agent.plan()
                    print(f"\n{'='*60}")
                    print(f"Phase: {phase_name.strip().upper()} — {len(plan)} action(s)")
                    for p in plan:
                        print(f"  → {p.get('description', p.get('action', ''))}")
            return

        # Run phases
        phases = args.phase.split(",") if args.phase else None
        if phases:
            phases = [p.strip() for p in phases]

        results = orch.run_all(phases=phases)

        # Print summary
        print(f"\n{'='*60}")
        print("EXECUTION COMPLETE")
        print(f"{'='*60}")
        kb = results.get("kb_summary", {})
        print(f"  Assets:          {kb.get('assets', 0)}")
        print(f"  Endpoints:       {kb.get('endpoints', 0)}")
        print(f"  Vulnerabilities: {kb.get('vulnerabilities', 0)}")
        sev = kb.get("vulnerabilities_by_severity", {})
        if sev:
            print(f"    Critical: {sev.get('Critical', 0)} | High: {sev.get('High', 0)} | "
                  f"Medium: {sev.get('Medium', 0)} | Low: {sev.get('Low', 0)}")
        print(f"  PoC Results:     {kb.get('poc_results', 0)} ({kb.get('poc_verified', 0)} verified)")
        print(f"  Evidence:        {kb.get('evidence', 0)}")
        print(f"  Attack Paths:    {kb.get('attack_paths', 0)}")
        print(f"{'='*60}\n")

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Shutting down...")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

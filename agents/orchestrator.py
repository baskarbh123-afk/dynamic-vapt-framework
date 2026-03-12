#!/usr/bin/env python3
"""
Penetration Testing Agent Orchestrator
=======================================
Reads config.yaml and agent definitions to coordinate multi-agent
penetration testing across OWASP Top 10 categories.

Usage:
  python3 agents/orchestrator.py                    # Run all enabled agents
  python3 agents/orchestrator.py --agent 01         # Run specific agent
  python3 agents/orchestrator.py --agent 01,03,10   # Run multiple agents
  python3 agents/orchestrator.py --list             # List all agents and status
  python3 agents/orchestrator.py --plan             # Show execution plan
  python3 agents/orchestrator.py --status           # Show agent progress
  python3 agents/orchestrator.py --report           # Generate agent summary
"""

import yaml
import os
import sys
import json
import logging
import glob
from datetime import datetime
from pathlib import Path
from collections import OrderedDict

# ============================================================================
# Constants
# ============================================================================
BASE_DIR = Path(__file__).parent.parent.resolve()
AGENTS_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = BASE_DIR / "config.yaml"
LOG_DIR = BASE_DIR / "logs"
AGENT_LOG = LOG_DIR / "agent_execution.log"
AGENT_STATUS_FILE = LOG_DIR / "agent_status.json"

# Priority sort order
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# ============================================================================
# Logging
# ============================================================================
def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [orchestrator] %(message)s",
        handlers=[
            logging.FileHandler(AGENT_LOG),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger("orchestrator")

# ============================================================================
# Config & Agent Loading
# ============================================================================
def load_config():
    if not CONFIG_FILE.exists():
        print(f"[ERROR] config.yaml not found at {CONFIG_FILE}")
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)

def load_agent(filepath):
    """Load a single agent YAML definition."""
    with open(filepath) as f:
        return yaml.safe_load(f)

def load_all_agents():
    """Load all agent YAML files from agents/ directory."""
    agents = []
    for fpath in sorted(AGENTS_DIR.glob("agent_*.yaml")):
        try:
            agent_data = load_agent(fpath)
            agent_data["_file"] = fpath.name
            agents.append(agent_data)
        except Exception as e:
            print(f"[WARNING] Failed to load {fpath.name}: {e}")
    return agents

def get_agent_number(agent_data):
    """Extract agent number from ID (e.g., 'agent-01-access-control' -> '01')."""
    agent_id = agent_data.get("agent", {}).get("id", "")
    parts = agent_id.split("-")
    if len(parts) >= 2:
        return parts[1]
    return "00"

# ============================================================================
# Module ↔ Config Mapping
# ============================================================================
def get_enabled_modules(config):
    """Get set of enabled exploitation modules from config.yaml preferences."""
    prefs = config.get("preferences", {})
    modules = prefs.get("exploitation_modules", {})
    return {k for k, v in modules.items() if v}

def agent_modules_match_config(agent_data, enabled_modules):
    """Check which of an agent's modules are enabled in config."""
    agent_modules = agent_data.get("modules", [])
    matched = []
    skipped = []
    
    for mod in agent_modules:
        mod_path = mod.get("path", "")
        # Extract module name from path for matching
        mod_name = Path(mod_path).stem.lower()
        
        # Check if module is enabled in config
        if mod_name in enabled_modules or _fuzzy_module_match(mod_name, enabled_modules):
            matched.append(mod)
        else:
            skipped.append(mod)
    
    return matched, skipped

def _fuzzy_module_match(mod_name, enabled_modules):
    """Fuzzy match module name against config entries."""
    # Handle naming differences (e.g., SESSION_HANDLING vs session_handling)
    normalized = mod_name.lower().replace("-", "_")
    for em in enabled_modules:
        if normalized == em.lower().replace("-", "_"):
            return True
        # Also match partial names
        if normalized in em.lower() or em.lower() in normalized:
            return True
    return False

# ============================================================================
# Agent Status Management
# ============================================================================
def load_agent_status():
    """Load agent execution status from JSON file."""
    if AGENT_STATUS_FILE.exists():
        with open(AGENT_STATUS_FILE) as f:
            return json.load(f)
    return {}

def save_agent_status(status):
    """Save agent execution status to JSON file."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(AGENT_STATUS_FILE, "w") as f:
        json.dump(status, f, indent=2, default=str)

def update_agent_status(agent_id, state, details=None):
    """Update status for a specific agent."""
    status = load_agent_status()
    status[agent_id] = {
        "state": state,
        "updated": datetime.now().isoformat(),
        "details": details or {}
    }
    save_agent_status(status)

# ============================================================================
# Execution Plan
# ============================================================================
def build_execution_plan(agents, config):
    """Build prioritized execution plan based on config and agent priorities."""
    enabled_modules = get_enabled_modules(config)
    plan = []
    
    for agent_data in agents:
        agent_info = agent_data.get("agent", {})
        agent_num = get_agent_number(agent_data)
        matched, skipped = agent_modules_match_config(agent_data, enabled_modules)
        
        plan.append({
            "number": agent_num,
            "id": agent_info.get("id", ""),
            "name": agent_info.get("name", ""),
            "owasp": agent_info.get("owasp_category", ""),
            "priority": agent_info.get("priority", "medium"),
            "matched_modules": len(matched),
            "total_modules": len(agent_data.get("modules", [])),
            "skipped_modules": len(skipped),
            "modules": matched,
            "skipped": skipped,
            "cwe_count": len(agent_data.get("cwe_coverage", [])),
            "execution_steps": len(agent_data.get("execution_order", [])),
            "requires": agent_data.get("requires", []),
            "findings_prefix": agent_data.get("findings_prefix", ""),
            "_file": agent_data.get("_file", ""),
        })
    
    # Sort by priority
    plan.sort(key=lambda x: PRIORITY_ORDER.get(x["priority"], 99))
    return plan

# ============================================================================
# Display Functions
# ============================================================================
def display_agent_list(agents, config):
    """Display all agents with their status."""
    plan = build_execution_plan(agents, config)
    status = load_agent_status()
    
    print("\n" + "=" * 80)
    print("  PENETRATION TESTING AGENTS — OVERVIEW")
    print("=" * 80)
    print(f"  {'#':<4} {'Agent':<30} {'OWASP':<12} {'Priority':<10} {'Modules':<10} {'CWEs':<6} {'Status':<12}")
    print("-" * 80)
    
    for p in plan:
        agent_status = status.get(p["id"], {}).get("state", "pending")
        mod_str = f"{p['matched_modules']}/{p['total_modules']}"
        print(f"  {p['number']:<4} {p['name']:<30} {p['owasp'][:11]:<12} {p['priority']:<10} {mod_str:<10} {p['cwe_count']:<6} {agent_status:<12}")
    
    total_cwe = sum(p["cwe_count"] for p in plan)
    total_mod = sum(p["matched_modules"] for p in plan)
    print("-" * 80)
    print(f"  {'TOTAL':<4} {'':<30} {'':<12} {'':<10} {total_mod:<10} {total_cwe:<6}")
    print("=" * 80 + "\n")

def display_execution_plan(agents, config):
    """Display detailed execution plan."""
    plan = build_execution_plan(agents, config)
    
    print("\n" + "=" * 80)
    print("  AGENT EXECUTION PLAN")
    print("=" * 80)
    
    for i, p in enumerate(plan, 1):
        print(f"\n  [{i}] {p['name']} (Agent {p['number']})")
        print(f"      OWASP: {p['owasp']}")
        print(f"      Priority: {p['priority'].upper()}")
        print(f"      CWEs: {p['cwe_count']} | Modules: {p['matched_modules']}/{p['total_modules']}")
        print(f"      Findings prefix: {p['findings_prefix']}")
        
        if p["skipped_modules"] > 0:
            print(f"      Skipped (disabled in config): {p['skipped_modules']} module(s)")
        
        print(f"      Modules to execute:")
        for mod in p["modules"]:
            print(f"        → {mod.get('description', mod.get('path', ''))}")
        
        if p["requires"]:
            print(f"      Pre-conditions:")
            for req in p["requires"]:
                print(f"        ◆ {req}")
    
    print("\n" + "=" * 80)
    print(f"  Execution order: {' → '.join(p['number'] for p in plan)}")
    print(f"  Total agents: {len(plan)} | Total modules: {sum(p['matched_modules'] for p in plan)}")
    print(f"  Total CWEs covered: {sum(p['cwe_count'] for p in plan)}")
    print("=" * 80 + "\n")

def display_status(agents, config):
    """Display current agent execution status."""
    plan = build_execution_plan(agents, config)
    status = load_agent_status()
    
    print("\n" + "=" * 80)
    print("  AGENT EXECUTION STATUS")
    print("=" * 80)
    
    completed = 0
    in_progress = 0
    pending = 0
    findings_total = 0
    
    for p in plan:
        agent_st = status.get(p["id"], {})
        state = agent_st.get("state", "pending")
        details = agent_st.get("details", {})
        findings = details.get("findings_count", 0)
        findings_total += findings
        updated = agent_st.get("updated", "")
        
        if state == "completed":
            icon = "✓"
            completed += 1
        elif state == "in_progress":
            icon = "►"
            in_progress += 1
        elif state == "failed":
            icon = "✗"
        else:
            icon = "○"
            pending += 1
        
        print(f"  {icon} Agent {p['number']} — {p['name']:<30} [{state}] Findings: {findings}")
        if updated:
            print(f"    Last updated: {updated}")
    
    print("-" * 80)
    print(f"  Completed: {completed} | In Progress: {in_progress} | Pending: {pending}")
    print(f"  Total findings: {findings_total}")
    print("=" * 80 + "\n")

def generate_agent_report(agents, config):
    """Generate a summary report of agent execution."""
    plan = build_execution_plan(agents, config)
    status = load_agent_status()
    eng = config.get("engagement", {})
    
    report_path = BASE_DIR / "reports" / "AGENT_SUMMARY.md"
    
    content = f"""# Agent Execution Summary
> Engagement: {eng.get('name', 'N/A')}
> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Agent Results

| Agent | OWASP | Priority | Modules | CWEs | Findings | Status |
|-------|-------|----------|---------|------|----------|--------|
"""
    total_findings = 0
    for p in plan:
        agent_st = status.get(p["id"], {})
        state = agent_st.get("state", "pending")
        findings = agent_st.get("details", {}).get("findings_count", 0)
        total_findings += findings
        content += f"| Agent {p['number']} — {p['name']} | {p['owasp']} | {p['priority']} | {p['matched_modules']}/{p['total_modules']} | {p['cwe_count']} | {findings} | {state} |\n"
    
    content += f"""
---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Agents | {len(plan)} |
| CWEs Covered | {sum(p['cwe_count'] for p in plan)} |
| Modules Executed | {sum(p['matched_modules'] for p in plan)} |
| Total Findings | {total_findings} |

---

## CWE Coverage by Agent

"""
    for p in plan:
        agent_st = status.get(p["id"], {})
        state = agent_st.get("state", "pending")
        content += f"### Agent {p['number']} — {p['name']} [{state}]\n\n"
        
        # Load agent YAML for CWE details
        agent_file = AGENTS_DIR / p["_file"]
        if agent_file.exists():
            agent_data = load_agent(agent_file)
            for cwe in agent_data.get("cwe_coverage", []):
                content += f"- **{cwe['id']}**: {cwe['name']} — {cwe.get('test', '')}\n"
        content += "\n"
    
    content += "---\n\n*Report generated by Agent Orchestrator*\n"
    
    with open(report_path, "w") as f:
        f.write(content)
    
    print(f"\n[OK] Agent summary report generated: reports/AGENT_SUMMARY.md")
    return report_path

# ============================================================================
# Agent Execution
# ============================================================================
def execute_agent(agent_data, config, logger):
    """Execute a single agent's test plan."""
    agent_info = agent_data.get("agent", {})
    agent_id = agent_info.get("id", "unknown")
    agent_name = agent_info.get("name", "Unknown Agent")
    agent_num = get_agent_number(agent_data)
    
    logger.info(f"{'='*60}")
    logger.info(f"STARTING: Agent {agent_num} — {agent_name}")
    logger.info(f"OWASP: {agent_info.get('owasp_category', 'N/A')}")
    logger.info(f"Priority: {agent_info.get('priority', 'N/A')}")
    logger.info(f"{'='*60}")
    
    # Update status
    update_agent_status(agent_id, "in_progress", {
        "started": datetime.now().isoformat(),
        "agent_name": agent_name,
        "findings_count": 0
    })
    
    # Check pre-conditions
    requires = agent_data.get("requires", [])
    if requires:
        logger.info(f"Pre-conditions for {agent_name}:")
        for req in requires:
            logger.info(f"  ◆ {req}")
    
    # List CWEs being tested
    cwe_list = agent_data.get("cwe_coverage", [])
    logger.info(f"CWE coverage: {len(cwe_list)} weaknesses")
    for cwe in cwe_list:
        logger.info(f"  {cwe['id']}: {cwe['name']}")
    
    # List modules
    modules = agent_data.get("modules", [])
    logger.info(f"Modules to execute: {len(modules)}")
    for mod in modules:
        mod_path = mod.get("path", "")
        full_path = BASE_DIR / mod_path
        exists = full_path.exists() or full_path.is_symlink()
        status_str = "[OK]" if exists else "[MISSING]"
        logger.info(f"  {status_str} {mod.get('description', mod_path)}")
    
    # List execution steps
    steps = agent_data.get("execution_order", [])
    logger.info(f"Execution steps: {len(steps)}")
    for step in steps:
        logger.info(f"  Step {step['step']}: {step['action']}")
    
    # Mark as completed (actual exploitation is manual/AI-driven)
    update_agent_status(agent_id, "ready", {
        "started": datetime.now().isoformat(),
        "agent_name": agent_name,
        "findings_count": 0,
        "cwe_count": len(cwe_list),
        "module_count": len(modules),
        "status": "Agent loaded — ready for manual/AI-driven execution"
    })
    
    logger.info(f"Agent {agent_num} — {agent_name}: READY for execution")
    logger.info(f"{'='*60}\n")

def run_agents(agent_numbers, agents, config, logger):
    """Run specified agents in priority order."""
    plan = build_execution_plan(agents, config)
    
    if agent_numbers:
        # Filter to requested agents
        plan = [p for p in plan if p["number"] in agent_numbers]
    
    if not plan:
        logger.error("No agents matched the requested filter.")
        return
    
    logger.info(f"Executing {len(plan)} agent(s): {', '.join(p['number'] for p in plan)}")
    
    for p in plan:
        agent_file = AGENTS_DIR / p["_file"]
        agent_data = load_agent(agent_file)
        execute_agent(agent_data, config, logger)

# ============================================================================
# Main
# ============================================================================
def main():
    config = load_config()
    agents = load_all_agents()
    
    if not agents:
        print("[ERROR] No agent files found in agents/ directory.")
        sys.exit(1)
    
    if "--list" in sys.argv:
        display_agent_list(agents, config)
        return
    
    if "--plan" in sys.argv:
        display_execution_plan(agents, config)
        return
    
    if "--status" in sys.argv:
        display_status(agents, config)
        return
    
    if "--report" in sys.argv:
        generate_agent_report(agents, config)
        return
    
    # Parse --agent flag
    agent_numbers = None
    for i, arg in enumerate(sys.argv):
        if arg == "--agent" and i + 1 < len(sys.argv):
            agent_numbers = [n.strip().zfill(2) for n in sys.argv[i + 1].split(",")]
            break
    
    logger = setup_logging()
    
    if agent_numbers:
        logger.info(f"Running specific agents: {agent_numbers}")
        run_agents(agent_numbers, agents, config, logger)
    else:
        logger.info("Running all enabled agents")
        run_agents(None, agents, config, logger)

if __name__ == "__main__":
    main()

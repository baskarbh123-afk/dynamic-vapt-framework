#!/usr/bin/env python3
"""
Base Agent — Abstract base class for all VAPT agents.
======================================================
All agents inherit from BaseAgent and implement:
  - plan()     → decide what to test
  - execute()  → run the tests
  - report()   → summarize results
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, List, Optional

from core.knowledge_base import KnowledgeBase
from core.tool_integrations import ToolIntegrations


class AgentState:
    """Tracks agent lifecycle state."""
    IDLE = "idle"
    PLANNING = "planning"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BaseAgent(ABC):
    """Abstract base for all penetration testing agents."""

    name: str = "BaseAgent"
    description: str = ""
    phase: str = ""  # recon, enumeration, vulnerability, exploit, attack_chain, report, notification

    def __init__(self, config: dict, kb: KnowledgeBase, tools: ToolIntegrations):
        self.config = config
        self.kb = kb
        self.tools = tools
        self.logger = logging.getLogger(f"agent.{self.name}")
        self.state = AgentState.IDLE
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self.results: List[dict] = []
        self.errors: List[str] = []

    def _log(self, msg: str, level: str = "info"):
        getattr(self.logger, level)(f"[{self.name}] {msg}")

    def _timestamp(self) -> str:
        return datetime.now().isoformat()

    @abstractmethod
    def plan(self) -> List[dict]:
        """Return a list of planned test actions.

        Each action is a dict with at least:
            {"action": "...", "target": "...", "description": "..."}
        """
        ...

    @abstractmethod
    def execute(self, plan: List[dict]) -> List[dict]:
        """Execute planned actions and return results.

        Each result dict should include:
            {"action": "...", "target": "...", "status": "...", "data": {...}}
        """
        ...

    @abstractmethod
    def report(self) -> dict:
        """Return a summary dict of this agent's findings."""
        ...

    def run(self) -> dict:
        """Full agent lifecycle: plan → execute → report."""
        self.started_at = self._timestamp()
        self.state = AgentState.PLANNING
        self._log(f"Starting — {self.description}")

        try:
            # Plan
            action_plan = self.plan()
            self._log(f"Planned {len(action_plan)} action(s)")

            # Execute
            self.state = AgentState.RUNNING
            self.results = self.execute(action_plan)
            self._log(f"Executed — {len(self.results)} result(s)")

            # Report
            self.state = AgentState.COMPLETED
            self.completed_at = self._timestamp()
            summary = self.report()
            self._log(f"Completed in {self._elapsed()}")
            return summary

        except Exception as e:
            self.state = AgentState.FAILED
            self.completed_at = self._timestamp()
            self.errors.append(str(e))
            self._log(f"Failed: {e}", level="error")
            return {"agent": self.name, "state": "failed", "error": str(e)}

    def _elapsed(self) -> str:
        if self.started_at and self.completed_at:
            start = datetime.fromisoformat(self.started_at)
            end = datetime.fromisoformat(self.completed_at)
            delta = end - start
            return f"{delta.total_seconds():.1f}s"
        return "N/A"

    def status(self) -> dict:
        return {
            "agent": self.name,
            "phase": self.phase,
            "state": self.state,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "results_count": len(self.results),
            "errors": self.errors,
        }

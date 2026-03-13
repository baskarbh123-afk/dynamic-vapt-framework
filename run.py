#!/usr/bin/env python3
"""
VAPT Framework — Main Entry Point
===================================
Launches the AI Orchestrator to coordinate multi-agent penetration testing.

Usage:
  python3 run.py                              # Run all phases
  python3 run.py --phase recon                # Run recon only
  python3 run.py --phase recon,enumeration    # Run specific phases
  python3 run.py --status                     # Show system status
  python3 run.py --tools                      # List available tools
  python3 run.py --dry-run                    # Plan only, don't execute
  python3 run.py --config engagement.yaml     # Use specific config
"""

import sys
from pathlib import Path

# Ensure project root is on path
ROOT = Path(__file__).parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.orchestrator import main

if __name__ == "__main__":
    main()

# Phase 01 — Reconnaissance

## Objective
Gather intelligence about the target application without direct interaction (passive) and with controlled interaction (active) to build a comprehensive understanding of the attack surface.

## Pre-Conditions
- [ ] config.yaml populated and `python3 setup.py` executed
- [ ] scope/targets.md reviewed and confirmed
- [ ] Authorization confirmed (RoE signed)

## Sub-Modules

| Module | Type | Description |
|--------|------|-------------|
| PASSIVE_RECON.md | Passive | OSINT, public data, DNS, certificate transparency |
| ACTIVE_RECON.md | Active | Technology fingerprinting, header analysis, WAF detection |
| SUBDOMAIN_ENUM.md | Passive/Active | Subdomain discovery and validation |

## Execution Order
1. PASSIVE_RECON.md — No direct target interaction
2. SUBDOMAIN_ENUM.md — DNS-based discovery
3. ACTIVE_RECON.md — Direct target interaction (after scope confirmation)

## Outputs
- targets/domain.md — Updated with discovered information
- targets/tech_stack.md — Updated with fingerprinted technologies
- targets/attack_surface.md — Initial attack surface mapping
- targets/endpoints.md — Initial endpoint list
- logs/engagement.log — Recon findings logged

## Completion Criteria
- [ ] All public DNS records documented
- [ ] Technology stack identified (backend, frontend, DB at minimum)
- [ ] WAF/CDN presence determined
- [ ] Subdomain enumeration complete
- [ ] Attack surface map initialized
- [ ] Phase marked complete in logs/phase_tracker.md

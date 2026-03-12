# Phase 02 — Enumeration

## Objective
Systematically identify and catalog all services, endpoints, authentication mechanisms, user roles, and potential entry points of the target application. Build on reconnaissance data to create a detailed map of the application's functionality and security controls.

## Pre-Conditions
- [ ] Phase 01 (Reconnaissance) completed
- [ ] targets/domain.md populated with discovered information
- [ ] targets/tech_stack.md populated with fingerprinted technologies
- [ ] Scope confirmed — all targets are in-scope

## Sub-Modules

| Module | Description |
|--------|-------------|
| SERVICE_ENUMERATION.md | Identify running services, ports, and protocols |
| WEB_ENUMERATION.md | Deep web application endpoint and functionality mapping |
| API_ENUMERATION.md | API endpoint discovery, schema analysis, versioning |
| AUTH_ENUMERATION.md | Authentication mechanism analysis and flow mapping |

## Execution Order
1. SERVICE_ENUMERATION.md — Identify services and ports
2. WEB_ENUMERATION.md — Map web application structure
3. API_ENUMERATION.md — Discover and document API surface
4. AUTH_ENUMERATION.md — Map authentication flows and session handling

## Outputs
- targets/endpoints.md — Fully populated endpoint inventory
- targets/attack_surface.md — Updated with enumeration findings
- docs/AUTH_FLOW.md — Authentication flow documentation
- docs/SESSION_HANDLING.md — Session management analysis
- logs/engagement.log — Enumeration findings logged

## Completion Criteria
- [ ] All accessible endpoints documented
- [ ] API schema documented (REST/GraphQL)
- [ ] Authentication flows mapped
- [ ] Session handling mechanisms identified
- [ ] Role-based access matrix validated
- [ ] Input vectors identified for each endpoint
- [ ] Phase marked complete in logs/phase_tracker.md

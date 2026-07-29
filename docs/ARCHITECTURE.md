# AISOC Architecture Specification

## Overview

The **AI SOC Analyst** platform is built on a modern modular architecture designed for high-performance security operations center workloads.

---

## 🏗️ Core Layers

### 1. Data Ingestion & Normalization Layer
- **OpenSearch Client** (`services/opensearch_client.py`): Queries OpenSearch indexers for recent Wazuh events (`wazuh-alerts-*`).
- **Normalizer** (`parser/alert_normalizer.py`): Converts unstructured JSON telemetry into a standardized `Alert` dataclass.

### 2. Detection & Intelligence Layer
- **IOC Extractor** (`parser/ioc_extractor.py`): Extracts IP addresses (classified by RFC 1918 / Loopback / Public / Multicast), domains, URLs, and cryptographic hashes (MD5, SHA1, SHA256).
- **Risk Engine** (`parser/risk_engine.py`): Computes severity risk levels based on Wazuh rule levels and context.
- **MITRE ATT&CK Mapper** (`mitre/mapper.py`): Maps rule identifiers to MITRE TTP techniques and tactics.
- **Threat Intel Engine** (`threat_intel/intel_engine.py`): Enriches public IPs across VirusTotal v3, AbuseIPDB v2, and AlienVault OTX.

### 3. AI Investigation Layer
- **Prompt Builder** (`ai/prompt_builder.py`): Constructs structured markdown prompts.
- **AI Analyzer** (`ai/incident_analyzer.py`): Communicates with local Ollama LLM (`llama3.2:3b`) with automated rule-based fallback logic.

### 4. Enterprise Web & REST Layer
- **Flask Framework** (`web_app.py`): Manages authentication (`auth/`), dashboards (`dashboard/`), and REST API endpoints (`/api/v1/health`).
- **Security Middleware**: Appears in `web_app.py` to enforce HSTS, CSP, and XSS headers.

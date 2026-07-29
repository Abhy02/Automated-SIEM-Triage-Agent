# AISOC Production Deployment Guide

## Overview

This guide outlines deployment procedures for production Security Operations Center environments.

---

## 🐳 Docker Deployment with Wazuh

1. **Deploy Single-Node Wazuh Stack**:
   ```bash
   cd wazuh-docker/single-node
   docker-compose up -d
   ```

2. **Verify Container Services**:
   ```bash
   docker ps
   ```
   Ensure `wazuh.dashboard`, `wazuh.manager`, and `wazuh.indexer` are in `Up` status.

---

## 🔒 Production Hardening Checklist

- [x] Change default secret key in `.env` (`SECRET_KEY`).
- [x] Ensure SSL cert verification is enabled in production environments.
- [x] Restrict bind address in `web_app.py` or deploy behind Nginx / Traefik reverse proxy with HTTPS.
- [x] Configure firewall rules restricting port 5000 access to authorized SOC network subnets.

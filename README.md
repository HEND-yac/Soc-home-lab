# SOC Home Lab — Wazuh · TheHive · Cortex · MISP · Active Directory

An open-source **Security Operations Center** built on Docker during an 8-week CyberCamp project. It covers the full incident lifecycle: **detection** (Wazuh), **threat intelligence** (MISP), **incident response** (TheHive) and **automated analysis** (Cortex), monitoring a Linux server and a Windows Active Directory domain, with secure remote access through Tailscale.

> Detection → automatic MISP IoC correlation → TheHive alert → Cortex enrichment → analyst verdict.

---

## Table of contents

1. [Architecture](#1-architecture)
2. [Components](#2-components)
3. [How the components communicate](#3-how-the-components-communicate)
4. [Detection rules](#4-detection-rules)
5. [End-to-end alert flow](#5-end-to-end-alert-flow)
6. [Scenarios](#6-scenarios)
7. [Configuration notes](#7-configuration-notes)
8. [Troubleshooting & lessons learned](#8-troubleshooting--lessons-learned)
9. [Limitations & next steps](#9-limitations--next-steps)
10. [Installation](#10-installation)
11. [Repository structure](#11-repository-structure)
12. [Glossary](#12-glossary)

---

## 1. Architecture

```
                         ┌──────────────── Tailscale mesh VPN (WireGuard) ────────────────┐
                         │      host "ubuntus" = subnet router for 172.16.0.0/12          │
                         └─────────────────────────────┬──────────────────────────────────┘
                                                       │
 ┌───────────────────────────── Docker host: ubuntus (192.168.182.129) ────────────────────────────┐
 │                                                                                                  │
 │  ┌─ single-node_default ─────────┐        ┌─ misp-docker-official_default ─┐                    │
 │  │ wazuh.manager  :1514 :55000   │──API──►│ misp-core / nginx  :8443        │                    │
 │  │ wazuh.indexer  :9200          │◄─sock──│ db · modules · redis · mail     │                    │
 │  │ wazuh.dashboard :443          │        └─────────────▲──────────────────┘                    │
 │  └──────────────┬────────────────┘                      │ API (MISP_2_1)                         │
 │                 │ API (custom-thehive)                  │                                        │
 │                 ▼                                       │                                        │
 │  ┌─ thehive-network ─────────────┐   API    ┌──────────┴──────┐                                 │
 │  │ thehive :9000                 │─────────►│ cortex :9001    │                                 │
 │  │ cassandra · elasticsearch     │◄─────────│ (MISP_2_1, ...) │                                 │
 │  └───────────────────────────────┘          └─────────────────┘                                 │
 └──────────────────────────────────────────────────────────────────────────────────────────────────┘
        ▲ agent :1514                                   ▲ agent :1514
 ┌──────┴───────────────┐                     ┌─────────┴──────────────────────────┐
 │ Ubuntu endpoint      │                     │ Windows Server + Active Directory  │
 │ Wazuh agent 001      │                     │ AD DS · DNS · GPOs · Wazuh agent   │
 └──────────────────────┘                     └────────────────────────────────────┘
```

---

## 2. Components

| Function | Tool | Deployment | Ports |
|---|---|---|---|
| SIEM / XDR | **Wazuh 4.12** | `wazuh-docker` **single-node** (manager, indexer, dashboard) | 1514 (agents), 1515 (enrollment), 55000 (API), 9200 (indexer), 443 (dashboard) |
| Threat intelligence (CTI) | **MISP** | official `misp-docker` (core, nginx, MariaDB, modules, Redis, mail) | 8443 (HTTPS) |
| Incident response | **TheHive 5** | `strangebee/thehive:5.2` + Cassandra + Elasticsearch | 9000 |
| Automated analysis | **Cortex 3** | single container started with `docker run` on `soc_net` (no compose), config bind-mounted from the host | 9001 |
| Remote access | **Tailscale** | on the host, configured as a **subnet router** | WireGuard |
| Linux endpoint | Ubuntu + Wazuh agent `001` | — | → 1514 |
| Windows endpoint | Windows Server + **Active Directory** (AD DS, DNS, file services) + Wazuh agent | — | → 1514 |

**Why single-node Wazuh?** A multi-node cluster (master + workers, replicated indexers) brings high availability for production-scale log volumes, at a large RAM/CPU cost. For a lab, single-node gives the same features with a fraction of the resources.

**Active Directory.** A domain controller simulates an enterprise network: organizational units, users and groups, and **Group Policy Objects (GPOs)** to centrally enforce security settings. AD is the primary target in real attacks (lateral movement, privilege escalation, ransomware), so its Windows Security events (4624, 4625, 4688, 4769) are essential SOC telemetry.

---

## 3. How the components communicate

### 3.1 Docker networks
The stacks were deployed separately, each in its own bridge network, plus one shared network (`soc_net`) for the incident-response side:

| Network | Containers | Created by |
|---|---|---|
| `single-node_default` | wazuh.manager, wazuh.indexer, wazuh.dashboard | Wazuh `docker-compose.yml` |
| `misp-docker-official_default` | misp-core, nginx, db, modules, redis, mail | MISP `docker-compose.yml` |
| `prod1-thehive_thehive-network` | thehive, cassandra, thehive-elasticsearch | TheHive `docker-compose.yml` |
| **`soc_net`** | **thehive, thehive-elasticsearch, cortex** | `docker network create soc_net`, containers attached with `--network` / `docker network connect` |

**Cortex was not deployed with Docker Compose.** It was started manually with `docker run --network soc_net`, with its configuration bind-mounted from the host (`/home/hend/cortex-config/application.conf` → `/etc/cortex/application.conf`).

Containers resolve each other **by name only inside a shared network**, through Docker's embedded DNS. Thanks to `soc_net`:
- Cortex stores its data in TheHive's Elasticsearch at `http://thehive-elasticsearch:9200`;
- TheHive and Cortex talk to each other directly by container name.

Wazuh and MISP stay in their own networks, so traffic to and from them goes through the **host IP and published ports**: the Wazuh integration scripts call `http://192.168.182.129:9000` (TheHive) and `https://192.168.182.129:8443` (MISP), and Cortex reaches MISP the same way.

```
┌── single-node_default ──┐   host IP :8443   ┌── misp-docker-official_default ──┐
│ wazuh.manager           │──────────────────►│ misp-core / nginx                 │
│  ├─ custom-misp         │                   └───────────────▲──────────────────┘
│  ├─ custom-misp-hash    │   host IP :9000                   │ host IP :8443
│  └─ custom-thehive      │──────────┐                        │
└─────────────────────────┘          ▼                        │
                        ┌──────────────── soc_net ────────────┴───┐
                        │ thehive ◄──► cortex ──► thehive-elasticsearch │
                        └─────────────────────────────────────────┘
```

> The specification planned to put every component on `soc_net`. In the final setup it unifies TheHive, Cortex and Elasticsearch; Wazuh and MISP keep their own networks and are reached through published ports, which works just as well and mirrors a multi-host architecture.

### 3.2 Three communication mechanisms

| Mechanism | Used for | Details |
|---|---|---|
| **REST API + API key** | Wazuh → MISP, Wazuh → TheHive, TheHive ↔ Cortex, Cortex → MISP, TheHive ↔ MISP | HTTP(S) requests with JSON bodies, authenticated by an application API key in the `Authorization` header |
| **Unix socket** | integration script → Wazuh analysis engine | `custom-misp` writes its result to `/var/ossec/queue/sockets/queue`, read by `wazuh-analysisd`. Local, fast, no network stack |
| **Volumes / bind mounts** | configuration & persistence | Wazuh: named volumes (`wazuh_etc`, `wazuh_logs`, `wazuh_integrations`). Cortex: `application.conf` bind-mounted from the host. TheHive and MISP: configured through their web UIs / databases |

### 3.3 Tailscale
Tailscale builds a **WireGuard mesh VPN**: each enrolled device gets a stable `100.x.x.x` address. The host advertises the Docker range **`172.16.0.0/12` as a subnet route**, so remote devices can reach containers that don't run Tailscale themselves, with no port forwarding and nothing exposed to the Internet. Validated by reaching MISP's internal container IP over the tailnet and observing the traffic on `tailscale0` with `tcpdump`.

---

## 4. Detection rules

Rules are evaluated by `wazuh-analysisd` on every decoded event. Built-in rules live in `/var/ossec/ruleset/rules/`; custom rules in `/var/ossec/etc/rules/local_rules.xml` (IDs **100000–120000** to avoid conflicts).

### 4.1 Built-in rules (Linux authentication, from `/var/log/auth.log`)

| Rule | Level | File | Description | MITRE ATT&CK |
|---|---|---|---|---|
| **5710** | 5 | `0095-sshd_rules.xml` | sshd: login attempt with a **non-existent user** (`Invalid user … from <ip>`) | T1110.001, T1021.004 |
| **5503** | 5 | `0085-pam_rules.xml` | PAM: authentication failure for an **existing** account (`pam_unix`) | T1110.001 |
| **10100** | 4 | `0020-syslog_rules.xml` | **First time user logged in** | T1078 |

Rule 10100 (default ruleset):

```xml
<rule id="10100" level="4">
  <if_group>authentication_success</if_group>
  <if_fts />
  <group>authentication_success,</group>
  <description>First time user logged in.</description>
  <mitre><id>T1078</id></mitre>
</rule>
```

- `if_group authentication_success`: inherits from any successful-login rule (SSH accepted, PAM session opened, su/sudo).
- `if_fts`: **First-Time-Seen**, fires only the first time the user/source combination is observed (state kept in `/var/ossec/queue/fts/`).

Failed attempts (5710, 5503) followed by a first-time successful login (10100) from the same source is the classic *password guessing → valid account* pattern.

**Escalation by correlation.** Single level-4/5 events stay in the dashboard to avoid alert fatigue. Repetition is escalated by built-in correlation rules (`frequency` + `timeframe` + `same_source_ip`): 5710 → **5712** (SSH brute force, level 10), 5503 → **5551** (multiple PAM failures, level 10).

### 4.2 Custom rules: Wazuh × MISP IoC correlation

```xml
<group name="misp,">
  <rule id="100010" level="3">
    <decoded_as>json</decoded_as>
    <field name="integration">misp</field>
    <description>MISP: Wazuh alert enriched with threat intel data</description>
  </rule>

  <rule id="100011" level="12">
    <if_sid>100010</if_sid>
    <field name="misp.matches">\.+</field>
    <description>MISP: IOC match found for $(misp.ioc_value)</description>
    <group>misp,</group>
  </rule>
</group>
```

- **100010** (parent, level 3) catches every JSON event injected by the MISP integration (`integration: misp`).
- **100011** (child, level 12) fires only when `misp.matches` is not empty. In Wazuh's OS_Regex, `\.` means *any character*, so `\.+` = "at least one character", i.e. **MISP returned a match**. `$(misp.ioc_value)` prints the matched indicator.

### 4.3 Custom rules: Kerberoasting (Active Directory)

```xml
<group name="kerberos,windows,">
  <rule id="100200" level="5">
    <if_sid>60106</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <description>Kerberos TGS ticket requested (4769) - Kerberoasting reconnaissance</description>
    <mitre><id>T1558.003</id></mitre>
  </rule>

  <rule id="100201" level="12" frequency="10" timeframe="60">
    <if_matched_sid>100200</if_matched_sid>
    <same_field>win.system.computer</same_field>
    <description>Kerberoasting detected: 10+ TGS requests in 60s</description>
    <mitre><id>T1558.003</id></mitre>
  </rule>
</group>
```

A single Kerberos service-ticket request (4769) is normal. A burst of 10+ in 60 seconds from the same machine matches Kerberoasting: requesting tickets for accounts with an SPN, then cracking them offline.

---

## 5. End-to-end alert flow

```
1. DETECTION     Agent sends events ──► wazuh.manager :1514 ──► wazuh-analysisd applies decoders + rules
2. ENRICHMENT    wazuh-integratord runs custom-misp (IPs) and custom-misp-hash (file hashes)
                 ──► POST MISP /attributes/restSearch
                 ──► result written to the Unix socket ──► rule 100011 (level 12) on match
3. NOTIFICATION  custom-thehive turns alerts above the configured level into a JSON payload
                 ──► POST TheHive /api/v1/alert ──► Alert in TheHive
4. INVESTIGATION Analyst promotes the Alert to a Case; observables (IP, hash…) are attached
5. ANALYSIS      "Run analyzers" ──► Cortex MISP_2_1 (pymisp) ──► MISP ──► report in the Case
6. CTI SYNC      TheHive periodically imports new MISP events as Alerts (Platform Management → MISP)
```

**Automatic vs. manual enrichment.** Step 2 is automatic and turns an IoC match into a high-severity alert in real time. Step 5 is analyst-driven and returns a detailed report inside the case.

---

## 6. Scenarios

### Scenario 1: SSH unauthorized access attempt ✅ validated

| Step | What happened |
|---|---|
| Attack | Repeated SSH logins against the Ubuntu endpoint: non-existent users, wrong passwords, then a successful login |
| Detection | Rules **5710**, **5503**, **10100** on agent `001` |
| Threat intel | `custom-misp` looked up the source IP `192.168.182.1`. Match found, rule **100011** fired at level 12 |
| Escalation | Alert forwarded to TheHive; case opened with the IP as observable (TLP:AMBER, PAP:AMBER) |
| Enrichment | Cortex `MISP_2_1` report: `MISP:Search = "1 event(s)"`, taxonomy **suspicious** |
| Verdict | **True Positive**, closed with *No Impact*; recommendation: block the IP, monitor related connections |

IoCs:

| Type | Value |
|---|---|
| Source IP | `192.168.182.1` (simulated attacker; VMware NAT gateway in the lab) |
| MISP event | `#8` "malicious ip address", threat level **High** (1) |
| MISP event UUID | `3998b221-efbc-4329-8b9d-8a0dcbf05e6b` |

Example command used to generate failed attempts:

```bash
for i in {1..10}; do ssh baduser@<linux-endpoint> -o ConnectTimeout=2; done
```

### Scenario 2: Kerberoasting on Active Directory
Detection rules **100200 / 100201** are in place (Event ID 4769, T1558.003). Simulation approach: create a service account with an SPN (`setspn -A HTTP/service1 <user>`), then request service tickets with Rubeus or Impacket `GetUserSPNs.py`.

### Scenario 3: Malicious file hash via MISP
A second integration script, **`custom-misp-hash`**, is deployed on the manager and declared in `ossec.conf`. Approach: add a file hash as an IoC in MISP, monitor a directory with Wazuh **FIM (syscheck)**, and let the script look up the file hash in MISP to raise a critical alert on a match.

---

## 7. Configuration notes

### Cortex → MISP (analyzer `MISP_2_1`)
Configured in Cortex under **Organization → Analyzers → MISP_2_1 → Edit**. This setting is stored in Cortex's database and **overrides** *Analyzers Config*.

| Field | Value |
|---|---|
| url | `https://<docker-host>:8443` |
| key | MISP auth key (*Administration → List Auth Keys → Add authentication key*) |
| cert_check | `False` (self-signed certificate, lab only) |

Connectivity test:

```bash
curl -k -H "Authorization: <MISP_API_KEY>" -H "Accept: application/json" \
     https://<docker-host>:8443/servers/getVersion
```

### Where configuration lives

| Tool | Item | Location |
|---|---|---|
| Wazuh | custom rules / decoders | `/var/ossec/etc/rules/local_rules.xml`, `/var/ossec/etc/decoders/local_decoder.xml` |
| Wazuh | main config, integrations | `/var/ossec/etc/ossec.conf`, `/var/ossec/integrations/` |
| Wazuh | alerts / logs | `/var/ossec/logs/alerts/alerts.json`, `/var/ossec/logs/ossec.log` |
| Cortex | config / analyzers | `/etc/cortex/application.conf` (bind mount), `/opt/Cortex-Analyzers/analyzers/` |
| TheHive | config | web UI (*Platform Management*) |
| MISP | config | database (MariaDB) via web UI |

To copy a file out of the Wazuh manager container:

```bash
docker cp single-node_wazuh.manager_1:/var/ossec/etc/rules/local_rules.xml .
```

---

## 8. Troubleshooting & lessons learned

| Symptom | Root cause | Fix |
|---|---|---|
| Cortex: `PyMISPError … [Errno 113] No route to host` (`192.168.182.132`) | The Docker host got a new DHCP lease (`.132` → `.129`) | Update the URL **on the analyzer instance**, then run a **new** job. Reserve static IPs |
| Error still showed the old IP after editing | Only *Analyzers Config* was edited; the analyzer instance kept its own value | Edit `MISP_2_1` itself, or Disable/Enable it |
| `custom-misp` integration failing | Windows line endings (`\r\n`) in the script | Convert to Unix format (`dos2unix` / `sed -i 's/\r$//'`) |
| Analyzers not visible from TheHive | TheHive and Cortex organizations did not match | Align the organization and API key between TheHive and Cortex |
| Custom MISP rule never fired | Wrong parent rule matched first | Anchor the child with `if_sid` on a dedicated JSON parent rule (100010) |
| `ossec.conf` changes ignored after `docker restart` | Config copied by the entrypoint at container **creation** | `docker compose down && docker compose up -d` |
| Python packages lost in Cortex after re-creation | Installed in the running container, not in the image | Build a custom Cortex image (planned) |
| Wazuh *Events*: "No results match" | Time range start = end | Set the time picker to *Last 24 hours* |
| `FutureWarning: This class is deprecated` | `ExpandedPyMISP` deprecated | Harmless |

---

## 9. Limitations & next steps

**Limitations**
- RAM limits running every component at full load simultaneously.
- Docker networks only partly unified: `soc_net` links TheHive, Cortex and Elasticsearch; Wazuh and MISP are reached through published ports.
- `cert_check: false` and self-signed certificates: acceptable in a lab, not in production.

**Next steps**
- Run and document the Kerberoasting and malicious-hash scenarios end to end.
- Wazuh **active response** to block IPs confirmed malicious by MISP.
- Subscribe MISP to public feeds (CIRCL, abuse.ch).
- Hardening: non-root containers, Docker secrets, pinned image versions, Tailscale ACLs.
- Additional Cortex analyzers (AbuseIPDB, VirusTotal) and responders.

---

## 10. Installation

Step-by-step deployment commands (Wazuh, MISP, TheHive, Cortex, Tailscale, agents and a pipeline test) are in **[installation_guide.md](installation_guide.md)**.

---

## 11. Repository structure

```
Soc-home-lab/
├── README.md
├── installation_guide.md          deployment commands
├── .gitignore                     keeps .env, keys and certificates out of Git
├── docs/
│   ├── ARCHITECTURE.png           architecture diagram
│   └── CAHIER_DE_CHARGE.md        project specification (8-week plan)
└── docker/
    ├── wazuh/
    │   ├── docker-compose.yml     from wazuh/wazuh-docker (single-node)
    │   ├── local_rules.xml        custom rules 100010/100011, 100200/100201
    │   └── custom-misp.py         MISP integration script (API key and host as placeholders)
    ├── misp/
    │   └── docker-compose.yml     secrets read from .env (not committed)
    ├── thehive/
    │   └── docker-compose.yml     TheHive 5.2 + Cassandra + Elasticsearch
    └── cortex/
        └── application.conf       Cortex config, secret key replaced by a placeholder
```

Cortex has no compose file: it runs from a single `docker run` command (see [installation_guide.md](installation_guide.md)).

Third-party components (Wazuh Docker, MISP Docker, Cortex-Analyzers) are used from their official repositories and are not redistributed here. **No secrets are committed**: API keys, passwords and certificates are excluded or replaced by placeholders. The Wazuh compose file keeps the project's public default credentials, which must be changed in any real deployment.

---

## 12. Glossary

| Term | Definition |
|---|---|
| **SIEM** | Security Information and Event Management: collects and correlates logs to detect threats (Wazuh) |
| **IR** | Incident Response: handling an incident once detected (TheHive) |
| **CTI** | Cyber Threat Intelligence: structured knowledge of known threats, shared as IoCs (MISP) |
| **IoC** | Indicator of Compromise: IP, hash, domain… linked to known malicious activity |
| **SOAR** | Security Orchestration, Automation and Response: automated enrichment/response (partly Cortex) |
| **Decoder / Rule** | A decoder extracts fields from a raw log; a rule decides whether they are suspicious and how severe |
| **Observable** | Any technical artefact attached to a case (IP, hash, domain, email) |
| **Analyzer** | Cortex program that takes an observable and returns a report and taxonomies |
| **FTS** | First-Time-Seen: Wazuh option that fires only on the first occurrence of a value |
| **FIM / syscheck** | Wazuh File Integrity Monitoring: detects file creation, modification, deletion |

---

*SOC Home Lab · CyberCamp 2026*

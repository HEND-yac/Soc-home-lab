v# Cahier des Charges — Home Lab Security Operations Center

> **Projet :** SOC Home Lab (Docker)
> **Version :** 1.0 — Juin 2026
> **Durée :** 8 semaines (2 mois)
> **Stack :** Docker / Docker Compose

---

## Table des matières

1. [Contexte et objectifs](#1-contexte-et-objectifs)
2. [Architecture technique](#2-architecture-technique)
3. [Description détaillée des composants](#3-description-détaillée-des-composants)
4. [Planning semaine par semaine](#4-planning-semaine-par-semaine)
5. [Gestion des risques](#5-gestion-des-risques)
6. [Livrables et critères de succès](#6-livrables-et-critères-de-succès)

---

## 1. Contexte et objectifsv![m](image.png)

### 1.1 Contexte

Ce projet consiste à concevoir et déployer un environnement de **Security Operations Center (SOC)** complet dans un home lab. L'ensemble des composants est conteneurisé via **Docker** et orchestré par **Docker Compose**, permettant une installation reproductible, isolée et maintenable.

L'objectif pédagogique est de maîtriser les outils utilisés dans les SOC professionnels : collecte de logs (SIEM), gestion des incidents (IR), analyse automatisée d'observables et partage de renseignements sur les menaces (CTI). Le tout est relié par un réseau VPN maillé chiffré via **Tailscale**.

### 1.2 Objectifs généraux

- Déployer une infrastructure SOC complète en conteneurs Docker
- Comprendre l'architecture et la configuration de chaque outil de sécurité
- Établir les flux de communication entre les composants (alertes, IOC, analyses)
- Sécuriser les communications inter-conteneurs via Tailscale (WireGuard)
- Documenter chaque étape de déploiement et de configuration
- Simuler des scénarios d'attaque et valider la chaîne détection → réponse

### 1.3 Périmètre — Composants Docker

| Composant | Rôle | Image Docker |
|---|---|---|
| **Wazuh** | SIEM / XDR — collecte et corrélation d'alertes | `wazuh/wazuh-manager:4.7.x` |
| **TheHive** | Gestion des incidents et cas de sécurité | `strangebee/thehive:5` |
| **Cortex** | Analyse automatisée d'observables | `thehiveproject/cortex:3` |
| **MISP** | Plateforme de threat intelligence et IOC | `coolacid/misp-docker:latest` |
| **Active Directory** | Annuaire Windows, source de logs Sysmon | `dockurr/windows:latest` (AD DS) |
| **Linux Server** | Serveur Ubuntu supervisé par agent Wazuh | `ubuntu:22.04` + agent Wazuh |
| **Tailscale** | VPN mesh WireGuard reliant tous les conteneurs | `tailscale/tailscale:latest` |

---

## 2. Architecture technique

### 2.1 Infrastructure Docker

Chaque composant tourne dans un **conteneur Docker dédié**. L'orchestration est assurée par Docker Compose. Un réseau Docker interne isolé (`soc_net`) est créé pour les communications inter-conteneurs. Tailscale expose les services sur un réseau VPN maillé WireGuard accessible à distance via MagicDNS.

```
┌─────────────────────────────────────────────────────────────────┐
│                    TAILSCALE VPN MESH                           │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  WAZUH   │◄──►│ THE HIVE │◄──►│  CORTEX  │◄──►│   MISP   │  │
│  │SIEM/XDR  │    │    IR    │    │ Analyzer │    │  CTI     │  │
│  └────▲─────┘    └──────────┘    └──────────┘    └──────────┘  │
│       │                                                         │
│  ┌────┴─────┐    ┌──────────┐                                   │
│  │ ACTIVE   │    │  LINUX   │                                   │
│  │DIRECTORY │    │  SERVER  │                                   │
│  └──────────┘    └──────────┘                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Flux de communication

| Source | Destination | Protocole / Données | Direction |
|---|---|---|---|
| Linux Server | Wazuh | Filebeat / Auditd — logs système | → |
| Active Directory | Wazuh | Sysmon / WinEvt — événements Windows | → |
| Wazuh | TheHive | Alertes de sécurité → création de cas | ↔ |
| Wazuh | MISP | Flux de threat intelligence (IOC) | ↔ |
| TheHive | Cortex | Jobs d'analyse sur observables | ↔ |
| TheHive | MISP | Enrichissement IOC des cas | ↔ |
| Cortex | MISP | Lookup d'observables dans MISP | ↔ |
| Tailscale | Tous | WireGuard — chiffrement du tunnel VPN | ↔ |

### 2.3 Prérequis techniques

| Composant | Exigence |
|---|---|
| **Matériel** | 16 Go RAM minimum, 8 cœurs CPU, 200 Go SSD |
| **OS hôte** | Ubuntu Server 22.04 LTS ou Debian 12 |
| **Docker** | Docker Engine v24+ et Docker Compose v2.20+ |
| **Réseau** | Accès Internet pour pull des images, compte Tailscale (gratuit) |
| **Mémoire** | Wazuh seul requiert ~4 Go RAM ; prévoir 12 Go pour l'ensemble |

---

## 3. Description détaillée des composants

### 3.1 Wazuh — SIEM / XDR

Wazuh est une plateforme open-source de détection de menaces, de réponse aux incidents et de conformité. Elle est composée de **trois conteneurs distincts**.

**Architecture Docker (3 conteneurs) :**
- `wazuh-manager` — Moteur central d'analyse et de corrélation des logs. Reçoit les données des agents déployés sur les endpoints. Port 1514/UDP (agents), 55000/TCP (API REST)
- `wazuh-indexer` — Basé sur OpenSearch. Stocke et indexe toutes les alertes. Requiert ~2 Go RAM. Port 9200
- `wazuh-dashboard` — Interface web (Kibana-like) pour visualiser les alertes et rapports. Port 443

**Fonctionnalités clés :**
- Détection d'intrusion basée sur des règles (FIM, SCA, SIEM)
- Intégration native avec Active Directory (Sysmon, WinEvt)
- Support des agents Linux/Windows légers
- API REST pour intégration TheHive et MISP
- Règles MITRE ATT&CK embarquées

---

### 3.2 TheHive — Gestion des incidents

TheHive est une plateforme open-source de réponse aux incidents (IR). Elle permet de gérer des cas de sécurité, d'attribuer des tâches et d'automatiser la réponse via des playbooks.

**Architecture Docker :**
- `thehive` — Application backend Scala. Port 9000 (API + UI)
- `elasticsearch` — Persistance des cas, utilisateurs et observables

**Fonctionnalités clés :**
- Création automatique de cas depuis les alertes Wazuh via webhooks
- Gestion des observables (IP, domaine, hash, URL)
- Envoi automatique d'observables vers Cortex pour analyse
- Import/export d'IOC depuis MISP
- Gestion multi-tenant et RBAC (rôles utilisateurs)

---

### 3.3 Cortex — Moteur d'analyse

Cortex est le moteur d'analyse d'observables de TheHive Project. Il exécute des *analyzers* et des *responders* sur les observables issus des cas TheHive.

**Architecture Docker :**
- `cortex` — Service principal avec bibliothèque de +150 analyzers open-source. Port 9001

**Fonctionnalités clés :**
- Analyse automatisée d'IP, domaines, hashes, URLs, fichiers
- +150 analyzers intégrés (VirusTotal, Shodan, AbuseIPDB, MISP, etc.)
- Responders pour actions automatisées (bloquer une IP, enrichir un cas)
- Intégration native TheHive via clé API
- Support multi-worker pour paralléliser les analyses

---

### 3.4 MISP — Threat Intelligence

MISP (Malware Information Sharing Platform) est la référence open-source pour le partage de renseignements sur les menaces. Il structure les IOC selon les MISP Taxonomies et les exporte vers Wazuh et Cortex.vv

**Architecture Docker (3 conteneurs) :**
- `misp-core` — Application web PHP. Port 443
- `misp-modules` — Services d'enrichissement (whois, VirusTotal, passivedns…). Port 6666
- `misp-db` — Base MariaDB pour la persistance des événements

**Fonctionnalités clés :**
- Partage d'IOC structurés (IP, domaine, hash, e-mail, CVE…)
- Abonnement aux flux publics (CIRCL, Abuse.ch, MalwareBazaar, Feodo)
- Export STIX 2.0 / OpenIOC / CSV / Yara / Sigma
- API REST compatible TheHive et Cortex
- Corrélation automatique entre événements

---

### 3.5 Active Directory — Windows AD

Le contrôleur de domaine est simulé dans un conteneur Windows Server via l'image `dockurr/windows`, qui installe Windows Server 2022 avec AD DS. Il constitue la principale source de logs Windows.

**Architecture Docker :**
- `windows-ad` — Conteneur KVM-accelerated exposant Windows Server 2022 avec AD DS, DNS et Sysmon installé. Nécessite `--privileged` et `/dev/kvm`

> **Alternative légère :** Samba AD en conteneur Ubuntu si `/dev/kvm` n'est pas disponible.

**Fonctionnalités clés :**
- Source de logs Windows Event (Security, System, Application)
- Sysmon pour logs d'exécution de processus et connexions réseau
- Agent Wazuh Windows pour la collecte et l'envoi vers Wazuh Manager
- Simulation d'environnement entreprise réaliste (GPO, utilisateurs, groupes)

---

### 3.6 Linux Server — Endpoint supervisé

Serveur Ubuntu 22.04 représentant un endpoint typique. L'agent Wazuh collecte les logs auditd, syslog et filebeat.

**Architecture Docker :**
- `linux-server` — Conteneur Ubuntu 22.04 avec l'agent Wazuh 4.7.x installé et auditd configuré

**Fonctionnalités clés :**
- Collecte des logs système (auth.log, syslog, auditd)
- File Integrity Monitoring (FIM) sur les répertoires critiques
- Simulation d'activités normales et malveillantes pour test
- Surveillance de la conformité (CIS Benchmark Level 1)

---

### 3.7 Tailscale — VPN Mesh WireGuard

Tailscale est un réseau VPN maillé basé sur WireGuard. Il permet d'accéder à tous les services depuis n'importe quel appareil et sécurise les communications inter-conteneurs via un tunnel chiffré automatique.

**Architecture Docker :**
- `tailscale` — Conteneur sidecar ou subnet router. Expose tous les services sur le réseau Tailscale avec IP privée stable et MagicDNS

**Fonctionnalités clés :**
- Chiffrement WireGuard de bout en bout entre tous les nœuds
- Accès depuis mobile/laptop sans port forwarding
- ACL Tailscale pour contrôler les accès entre composants
- MagicDNS : `wazuh.tail`, `misp.tail`, `thehive.tail`…
- Gratuit jusqu'à 100 appareils (plan personnel)

---

## 4. Planning semaine par semaine

### Semaine 1 — Recherche globale & Infrastructure Docker
> **Objectif :** Comprendre l'écosystème SOC, préparer l'hôte Docker et déployer Tailscale.

| # | Tâche |
|---|---|
| 01 | Lecture des documentations officielles : Wazuh, TheHive, Cortex, MISP, Tailscale |
| 02 | Étude de l'architecture SOC et des flux de communication inter-composants |
| 03 | Installation et hardening de l'OS hôte (Ubuntu Server 22.04 LTS) |
| 04 | Installation de Docker Engine v24 et Docker Compose v2 |
| 05 | Création du `docker-compose.yml` de base avec réseau `soc_net` isolé |
| 06 | Déploiement et configuration du conteneur Tailscale (subnet router) |
| 07 | Création du compte Tailscale et génération des clés d'authentification (authkey) |
| 08 | Vérification de la connectivité VPN depuis un poste externe |
| 09 | Rédaction du journal de bord hebdomadaire et commit Git |

**Livrable :** Hôte Docker opérationnel, Tailscale actif, accès VPN validé, `docker-compose.yml` versionné

---

### Semaine 2 — Déploiement Wazuh (SIEM / XDR)
> **Objectif :** Déployer la stack Wazuh complète (manager + indexer + dashboard) et valider la collecte de logs.

| # | Tâche |
|---|---|
| 01 | Recherche approfondie : architecture Wazuh (manager, indexer, dashboard) |
| 02 | Étude du format de règles Wazuh et du moteur de décodeurs |
| 03 | Déploiement du conteneur `wazuh-manager` (ports 1514/UDP, 55000/TCP) |
| 04 | Déploiement du conteneur `wazuh-indexer` (OpenSearch, port 9200) |
| 05 | Déploiement du conteneur `wazuh-dashboard` (HTTPS port 443) |
| 06 | Configuration des certificats TLS auto-signés pour la stack |
| 07 | Configuration du fichier `ossec.conf` (règles actives, FIM, SCA) |
| 08 | Test de l'API REST Wazuh (authentification JWT, endpoints `/agents`) |
| 09 | Activation des règles MITRE ATT&CK et vérification des alertes dans le dashboard |

**Livrable :** Stack Wazuh opérationnelle, dashboard accessible via Tailscale, API fonctionnelle

---

### Semaine 3 — Active Directory & Linux Server (Agents Wazuh)
> **Objectif :** Déployer les endpoints supervisés (AD Windows et Linux) et connecter les agents Wazuh.

| # | Tâche |
|---|---|
| 01 | Recherche : Sysmon (configuration optimale, schéma SwiftOnSecurity) |
| 02 | Recherche : règles auditd et configuration Filebeat pour Linux |
| 03 | Déploiement du conteneur Windows Server 2022 avec AD DS (`dockurr/windows`) |
| 04 | Installation et configuration de Sysmon sur le contrôleur de domaine |
| 05 | Installation de l'agent Wazuh sur Windows et enrôlement auprès du Manager |
| 06 | Vérification des logs WinEvt (Security : 4624, 4625, 4688) dans Wazuh |
| 07 | Déploiement du conteneur Linux Server (Ubuntu 22.04) |
| 08 | Installation de l'agent Wazuh sur Linux et configuration d'auditd |
| 09 | Simulation de connexions SSH échouées et vérification des alertes générées |

**Livrable :** Agents Wazuh actifs sur AD et Linux, alertes visibles dans le dashboard

---

### Semaine 4 — Déploiement MISP (Threat Intelligence)
> **Objectif :** Déployer MISP, configurer les flux de threat intelligservices:
  misp-db:
    image: mariadb:10.11
    container_name: misp-db
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_USER: ${MYSQL_USER}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
      MYSQL_DATABASE: ${MYSQL_DATABASE}
    volumes:
      - misp-db-data:/var/lib/mysql
    networks:
      - soc_net

  misp-modules:
    image: coolacid/misp-docker:modules-latest
    container_name: misp-modules
    restart: unless-stopped
    networks:
      - soc_net

  misp-core:
    image: coolacid/misp-docker:core-latest
    container_name: misp-core
    restart: unless-stopped
    depends_on:
      - misp-db
      - misp-modules
    environment:
      MYSQL_HOST: misp-db
      MYSQL_USER: ${MYSQL_USER}
      MYSQL_PASSWORD: ${MYSQL_PASSWORD}
      MYSQL_DATABASE: ${MYSQL_DATABASE}
      BASE_URL: ${BASE_URL}
      ADMIN_EMAIL: ${MISP_ADMIN_EMAIL}
      ADMIN_PASSWORD: ${MISP_ADMIN_PASSPHRASE}
      TIMEZONE: ${TIMEZONE}
    ports:
      - "8443:443"
    volumes:
      - misp-core-data:/var/www/MISP
    networks:
      - soc_net

volumes:
  misp-db-data:
  misp-core-data:

networks:
  soc_net:
    external: trueence et l'intégrer avec Wazuh.

| # | Tâche |
|---|---|
| 01 | Recherche : modèle de données MISP (Event, Attribute, Object, Galaxy) |
| 02 | Recherche : formats d'export STIX 2.0, OpenIOC, Yara, Sigma |
| 03 | Étude des feeds publics : CIRCL, Abuse.ch, MalwareBazaar, Feodo |
| 04 | Déploiement de la stack MISP (`misp-core` + `misp-modules` + `mariadb`) |
| 05 | Configuration du certificat TLS et du domaine MISP via MagicDNS Tailscale |
| 06 | Activation et synchronisation des feeds publics CIRCL et Abuse.ch |
| 07 | Configuration de la clé API MISP pour Wazuh (module d'intégration) |
| 08 | Activation du module `wazuh-misp` dans `ossec.conf` pour enrichissement IOC |
| 09 | Test : insertion d'un IOC dans MISP, vérification de la détection dans Wazuh |

**Livrable :** MISP opérationnel, feeds actifs, intégration Wazuh–MISP validée avec IOC

---

### Semaine 5 — Déploiement TheHive (Incident Response)
> **Objectif :** Déployer TheHive 5, configurer la création automatique de cas depuis Wazuh et l'import MISP.

| # | Tâche |
|---|---|
| 01 | Recherche : modèle TheHive 5 (Case, Task, Observable, Alert, Responder) |
| 02 | Recherche : TheHive API v1 — endpoints d'alertes, cas, observables |
| 03 | Déploiement du conteneur TheHive 5 avec Elasticsearch (persistance) |
| 04 | Configuration du webhook Wazuh → TheHive (module `wazuh-thehive`) |
| 05 | Paramétrage des templates de cas et des taxonomies (TLP, PAP) |
| 06 | Configuration de la clé API TheHive pour l'intégration MISP |
| 07 | Import des événements MISP dans TheHive comme observables |
| 08 | Test end-to-end : alerte Wazuh → cas TheHive avec observables MISP enrichis |
| 09 | Configuration du RBAC (analyste, admin, readonly) |

**Livrable :** TheHive opérationnel, flux Wazuh→TheHive validé, import MISP fonctionnel

---

### Semaine 6 — Déploiement Cortex (Analyse automatisée)
> **Objectif :** Déployer Cortex, configurer les analyzers clés et relier Cortex à TheHive et MISP.

| # | Tâche |
|---|---|
| 01 | Recherche : analyzers Cortex (catégories : sandbox, OSINT, threat intel, réseau) |
| 02 | Recherche : développement d'un analyzer custom (Python SDK) |
| 03 | Déploiement du conteneur Cortex 3 (port 9001) |
| 04 | Configuration des analyzers prioritaires : MISP, AbuseIPDB, VirusTotal, Shodan |
| 05 | Liaison Cortex ↔ TheHive (clé API, organisation) |
| 06 | Liaison Cortex ↔ MISP (analyzer MISP Search) |
| 07 | Test : soumission d'un observable IP depuis TheHive → analyse Cortex → rapport |
| 08 | Configuration des responders (tagging MISP, enrichissement automatique) |
| 09 | Automatisation : déclenchement automatique de l'analyse à l'ouverture d'un cas |

**Livrable :** Cortex opérationnel, analyzers configurés, chaîne TheHive→Cortex→MISP validée

---

### Semaine 7 — Intégration complète & Scénarios de test
> **Objectif :** Valider la chaîne complète de détection à la réponse via des scénarios d'attaque simulés.

| # | Tâche |
|---|---|
| 01 | **Scénario 1** : Brute-force SSH sur Linux → alerte Wazuh → cas TheHive → analyse IP Cortex → IOC MISP |
| 02 | **Scénario 2** : Kerberoasting sur AD → alerte Wazuh (Event 4769) → cas TheHive → enrichissement |
| 03 | **Scénario 3** : Hash malveillant dans les logs → correspondance IOC MISP → alerte critique |
| 04 | Vérification de toutes les intégrations API (clés, webhooks, endpoints) |
| 05 | Optimisation des règles Wazuh (réduction des faux positifs) |
| 06 | Test de résilience Docker (redémarrage des conteneurs, persistance des données) |
| 07 | Vérification du chiffrement Tailscale sur toutes les communications |
| 08 | Audit de sécurité des conteneurs (ports exposés, volumes, secrets) |
| 09 | Création de dashboards Wazuh personnalisés (top alertes, timeline, géolocalisation) |

**Livrable :** 3 scénarios d'attaque documentés et validés, chaîne SOC complète opérationnelle

---

### Semaine 8 — Durcissement, Documentation & Présentation
> **Objectif :** Finaliser le projet : hardening des conteneurs, documentation complète et démonstration.

| # | Tâche |
|---|---|
| 01 | Hardening Docker : utilisateurs non-root, read-only filesystems, seccomp profiles |
| 02 | Gestion des secrets Docker (Docker Secrets ou `.env` chiffrés via `git-crypt`) |
| 03 | Revue des ACL Tailscale et restriction des flux autorisés entre conteneurs |
| 04 | Mise à jour de toutes les images Docker vers les dernières versions stables |
| 05 | Rédaction du README technique complet (installation, configuration, troubleshooting) |
| 06 | Documentation des runbooks pour les scénarios d'incident les plus fréquents |
| 07 | Création du fichier `docker-compose.prod.yml` avec les bonnes pratiques |
| 08 | Enregistrement d'une démonstration vidéo de la chaîne de détection complète |
| 09 | Publication du projet sur GitHub avec CI/CD basique (lint `docker-compose`) |

**Livrable :** Documentation complète, projet GitHub public, démonstration vidéo enregistrée

---

## 5. Gestion des risques

| Risque | Criticité | Mitigation |
|---|---|---|
| RAM insuffisante | 🔴 Élevée | Réduire le nombre de conteneurs actifs simultanément, activer le swap |
| Conflits de ports Docker | 🟡 Moyenne | Mapper les ports hôtes de façon unique dans `docker-compose.yml` |
| `/dev/kvm` absent (AD) | 🟡 Moyenne | Utiliser Samba AD en remplacement ou une VM séparée |
| API key compromise | 🔴 Élevée | Stocker les secrets dans Docker Secrets, ne jamais commiter dans Git |
| Tailscale outage | 🟢 Faible | Prévoir un accès direct (réseau Docker interne `soc_net`) en backup |
| Versioning images instables | 🟡 Moyenne | Épingler les versions d'images (tag exact, jamais `:latest` en prod) |

---

## 6. Livrables et critères de succès

### Livrables attendus

| Livrable | Description |
|---|---|
| `docker-compose.yml` | Fichier d'orchestration complet, versionné sur Git |
| Documentation technique | `README.md` + guides d'installation par composant |
| Runbooks | Procédures de réponse aux incidents les plus fréquents |
| Rapport de validation | Résultats des 3 scénarios de test |
| Journal de bord | Notes hebdomadaires de recherche et de déploiement |
| Démonstration vidéo | Walkthrough de la chaîne de détection complète |

### Critères de succès

| Critère | Validation |
|---|---|
| Tous les conteneurs démarrent sans erreur | `docker ps` affiche 7/7 conteneurs en état `Up` |
| Wazuh reçoit des logs de l'AD et du Linux Server | Agents visibles et actifs dans le dashboard Wazuh |
| Une alerte Wazuh crée automatiquement un cas TheHive | Cas visible dans TheHive avec observables associés |
| Les IOC MISP sont détectés par Wazuh | Alerte de niveau critique générée sur correspondance |
| Cortex analyse un observable depuis TheHive | Rapport d'analyse retourné dans le cas TheHive |
| Toutes les communications passent par Tailscale | `tcpdump` confirme le chiffrement WireGuard sur les flux |

---

*SOC Home Lab · v1.0 · 2026*

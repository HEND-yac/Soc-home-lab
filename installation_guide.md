# Installation guide — SOC Home Lab

Step-by-step commands to reproduce the lab. For the architecture, detection logic and scenarios, see the [README](README.md).

**Prerequisites:** Ubuntu 22.04 host, Docker Engine and Docker Compose v2, 16 GB RAM recommended.

**Secrets:** every value in angle brackets (`<MISP_API_KEY>`, `<docker-host>`…) must be replaced with your own. Never commit real keys or `.env` files.


Everything runs on one Ubuntu host with Docker Engine and Docker Compose v2. Replace `<docker-host>` with the host's IP.

## 1. Wazuh (single-node)

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.12.0
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator   # self-signed certificates
docker compose up -d
```

Dashboard: `https://<docker-host>` (default credentials are in the Wazuh documentation; change them).

Load the custom rules and the MISP integration from this repository:

```bash
docker cp docker/wazuh/local_rules.xml single-node_wazuh.manager_1:/var/ossec/etc/rules/local_rules.xml
docker cp docker/wazuh/custom-misp.py single-node_wazuh.manager_1:/var/ossec/integrations/custom-misp
docker exec single-node_wazuh.manager_1 bash -c \
  "chown root:wazuh /var/ossec/integrations/custom-misp && chmod 750 /var/ossec/integrations/custom-misp"
```

Declare the integration in `/var/ossec/etc/ossec.conf` (inside `<ossec_config>`):

```xml
<integration>
  <name>custom-misp</name>
  <hook_url>https://<docker-host>:8443/attributes/restSearch</hook_url>
  <api_key><MISP_API_KEY></api_key>
  <alert_format>json</alert_format>
</integration>
```

Then validate the rules and restart the manager:

```bash
docker exec single-node_wazuh.manager_1 /var/ossec/bin/wazuh-logtest   # optional: test a log line
docker compose down && docker compose up -d
```

## 2. MISP

```bash
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env        # set BASE_URL, admin email/password, ports (HTTPS 8443)
docker compose up -d
```

UI: `https://<docker-host>:8443`. Create an API key under *Administration → List Auth Keys*.

## 3. TheHive 5 + Cortex

TheHive (with Cassandra and Elasticsearch) can be deployed from StrangeBee's official Docker templates (`github.com/StrangeBee/docker`). UI: `http://<docker-host>:9000`.

Create the shared network and attach TheHive and its Elasticsearch to it, so Cortex can reach them by name:

```bash
docker network create soc_net
docker network connect soc_net thehive
docker network connect soc_net thehive-elasticsearch
```

Cortex, on `soc_net`, with its configuration bind-mounted from this repository:

```bash
docker run -d --name cortex -p 9001:9001 \
  --network soc_net \
  -v "$PWD/docker/cortex/application.conf:/etc/cortex/application.conf" \
  thehiveproject/cortex:3
```

UI: `http://<docker-host>:9001`. Then: create an organization and enable **MISP_2_1** (see *Configuration notes* in the [README](README.md#7-configuration-notes)), and link Cortex to TheHive with a Cortex API key (*TheHive → Platform Management → Connectors → Cortex*).

## 4. Tailscale (remote access)

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --advertise-routes=172.16.0.0/12
```

Approve the subnet route in the Tailscale admin console, then reach the services from any enrolled device.

## 5. Agents

Install the Wazuh agent on each endpoint and point it to the manager (`<address><docker-host></address>`, port 1514/tcp). Check with:

```bash
docker exec single-node_wazuh.manager_1 /var/ossec/bin/agent_control -l
```

## 6. Test the pipeline

```bash
for i in {1..10}; do ssh baduser@<linux-endpoint> -o ConnectTimeout=2; done
```

Expected: rules 5710/5503 in Wazuh, rule 100011 if the source IP exists in MISP, an alert in TheHive.

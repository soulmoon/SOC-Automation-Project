# SOC Automation Lab Project
A hands-on SOC (Security Operations Center) Automation Lab integrating powerful open-source tools like Wazuh (SIEM & XDR), TheHive (Case Management), and Shuffle (SOAR). This project showcases real-world detection, alerting, incident management, and automated response workflows.

---

## 🧰 Tools Used

- **Wazuh** – SIEM & XDR for log analysis, threat detection, and compliance.
- **TheHive** – Case management and incident response platform.
- **Shuffle** – SOAR (Security Orchestration, Automation, and Response) platform for automated workflows.
- **Sysmon** – Windows event logging tool for capturing telemetry.
- **Mimikatz** – Security tool used for generating malicious behavior in lab.
- **ElasticSearch & Cassandra** – Database components for storing logs and case data.

---

## 🔧 Lab Setup Overview
<img width="940" height="749" alt="image" src="https://github.com/user-attachments/assets/ae73b2f1-b064-4459-99e8-155cdb5544ba" />

# 1. Sysmon Installation on Windows 10
- Download and unzip Sysmon from Sysinternals.
- Download Olaf’s Sysmon config (XML).
- Install via PowerShell:
  .\Sysmon.exe -i sysmonconfig.xml

# 2. Wazuh Server on AWS (Ubuntu 22.04)
- sudo apt update && sudo apt upgrade -y
- curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
- Access Wazuh Dashboard via web browser (credentials shown after installation).
  
- Add Windows agents via dashboard.
  <img width="850" height="325" alt="image" src="https://github.com/user-attachments/assets/6f62eee4-eece-4787-91f0-16cc14b30049" />

# 3. TheHive Server on AWS (Ubuntu 22.04)
## - Install Java:
- wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
- echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
- sudo apt update
- sudo apt install java-common java-11-amazon-corretto-jdk

## - Install Cassandra:
- wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
- echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee /etc/apt/sources.list.d/cassandra.sources.list
- sudo apt update && sudo apt install cassandra

## - Install Elasticsearch:
- wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
- sudo apt install apt-transport-https
- echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
- sudo apt update && sudo apt install elasticsearch

## - Install TheHive:
- wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
- echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee /etc/apt/sources.list.d/strangebee.list
- sudo apt update && sudo apt install -y thehive
- Default login: admin@thehive.local / secret


# 4. 🧪 Configuration
## - Cassandra (TheHive DB)
- sudo nano /etc/cassandra/cassandra.yaml
- Modify:
  - cluster_name: 'dipaklab'
  - listen_address: <TheHive Public IP>
  - rpc_address: <TheHive Public IP>
  - seeds: "<TheHive Public IP>:7000"
- sudo systemctl stop cassandra
- sudo rm -rf /var/lib/cassandra/*
- sudo systemctl start cassandra

## - ElasticSearch
- sudo nano /etc/elasticsearch/elasticsearch.yml
- Modify:
  - cluster.name: thehive
  - node.name: node-1
  - network.host: 0.0.0.0
  - http.port: 9200
  - cluster.initial_master_nodes: ["node-1"]
- sudo systemctl enable elasticsearch && sudo systemctl start elasticsearch

## - TheHive
- sudo chown -R thehive:thehive /opt/thp
- sudo nano /etc/thehive/application.conf
- Modify:
  - hostname = ["<Public IP>"]
  - cluster-name = "dipaklab"
  - application.baseUrl = "http://<Public IP>:9000"
  - sudo systemctl enable thehive && sudo systemctl start thehive

# 5. 🔍 Wazuh Agent Log Ingestion
## - Login to Win10
- Edit Sysmon Event Channel in:
- Go to C:\Program Files (x86)\ossec-agent\ossec.conf
  - <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
- Restart Wazuh agent:
-   net start wazuhsvc

## - Enable log archival: (in Wazuh Server)
- sudo nano /var/ossec/etc/ossec.conf
- Add:
  -<logall>yes</logall>
  -<logall_json>yes</logall_json>
- sudo systemctl restart wazuh-manager

## - Enable Filebeat archive collection: (In Wazuh Server)
- sudo nano /etc/filebeat/filebeat.yml
- Add:
  - archive:
  - enabled: true
- sudo systemctl restart filebeat

## - Add a new index pattern in Wazuh Dashboard:
- Index Name: wazuh-archives-**
- Time Field: timestamp
- <img width="940" height="337" alt="image" src="https://github.com/user-attachments/assets/0f41d4a8-68a2-4ef8-bd95-0cee698ee6ba" />


# 6.⚡ Trigger Alerts Using Mimikatz
- Download and run mimikatz.exe on Win10.
- Rename file to abc.exe to test detection.
- Observe alert creation in Wazuh.
- <img width="940" height="353" alt="image" src="https://github.com/user-attachments/assets/b1195a2f-660e-4dc5-9913-2af7ab069794" />
- <img width="940" height="231" alt="image" src="https://github.com/user-attachments/assets/f8141ee0-d1d8-4189-a830-30a03b15dd03" />


# 7. 🔁 Integrate with Shuffle (SOAR)
## - Login to Shuffle, create a workflow.
- Add a Webhook trigger and copy the URI.
- Update ossec.conf:
  - <integration>
  - <name>shuffle</name>
  - <hook_url>https://shuffler.io/api/v1/hooks/webhook_xxxx</hook_url>
  - <rule_id>100002</rule_id>
  - <alert_format>json</alert_format>
  -</integration>
  
## - Restart Wazuh manager:
- sudo systemctl restart wazuh-manager
- 
## - Trigger Mimikatz again to verify the workflow in Shuffle.
- <img width="790" height="381" alt="image" src="https://github.com/user-attachments/assets/b4fc5c0a-664f-4fe1-8d2a-3d030121f930" />

# 8. 🔒 Security Note
This lab is intended only for educational and testing purposes in isolated environments. Never expose these services to the public internet without proper security configurations.

# 📧 Contact
Dipak Pakhrin



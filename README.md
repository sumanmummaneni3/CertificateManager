# 🔐 Certificate Manager — Network SSL Certificate Discovery & Monitoring Tool

**Certificate Manager** is a lightweight CLI tool that discovers, inventories, and monitors X.509/SSL certificates across your network and alerts before they expire.

Built for **MSPs, DevOps engineers, and system administrators**, it helps prevent outages caused by forgotten or expiring certificates.

Supports standalone environments and **NinjaOne agent-based deployments**.
---

# 🚨 Why this tool exists

Expired certificates break production systems, websites, and internal services.

Most teams:
- Don't know where all certificates exist
- Track them manually in spreadsheets
- Discover expiry only after outage

Certificate Manager automatically discovers certificates across your infrastructure and alerts before they expire.

---

# ⭐ Key Features

### 🔍 Network Certificate Discovery
Scan servers and endpoints to identify SSL certificates across ports.

### 📅 Expiry Monitoring & Alerts
Detect expiring certificates early and avoid outages.

### 🔐 Java Keystore Integration
Store and manage discovered certificates using Java Keystore.

### 🤖 NinjaOne Integration
Run via NinjaOne agents to:
- Discover certificates remotely
- Store results centrally
- Monitor managed client environments

### ⚡ Lightweight CLI
Fast, scriptable, and automation-friendly.

---

# 🖥 Example Output
```
% ./CertManager -nj — scan 192.168.1.1 --port 443
Checking 192.168.1.1... Saved.
[ {
"alias" : "192.168.1.1",
"expiryDate" : "2036-10-06",
"daysRemaining" : 3887,
"status" : "OK"
} ]


## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/sumanmummaneni3/CertificateManager.git
   cd CertificateManager

2. **Build and Install the project**
3. ```bash
   % ./gradlew clean build
   % cd build/installer

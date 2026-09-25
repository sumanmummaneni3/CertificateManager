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
```

# 🔎 Certificate audit (`-audit`)

Runs an external, evidence-first assessment of a list of hosts. It uses public data plus one
standard TLS handshake per address on the listed port:

- **Served state:** every A/AAAA address is handshaken with SNI; different leaves or chains behind
  one name are flagged (`NODE_DIVERGENCE`).
- **Chains:** missing intermediates, AIA-only completion, wrong order, root included, expired or
  weak certificates. With `--baseline <previous audit json>`, a chain that changed under an unchanged
  leaf is flagged too.
- **Certificate Transparency (crt.sh):** currently valid certificates for the domain that no audited
  endpoint serves.
- **CAA:** effective policy per RFC 8659, missing `accounturi` / `validationmethods` and
  unrestricted wildcards.

```
java -jar CertificateManager.jar -audit --csv targets.csv --requester "Your Name" --basis CONSENT --out ./audit
```

`targets.csv` needs a header row: `host` (required), `port`, `domain`, `owner`, `tags`. Each run
writes four files: a JSON export, a findings CSV (with why-it-matters and remediation), a coverage
CSV that lists every check that failed or did not run, and a Markdown report to finish by hand.
**A subject only counts as clean when its checks are OK in the coverage file.** crt.sh is
rate-limited to one request every 12.5 s, so CT takes about 25 seconds per domain. When crt.sh is
down, its error is reported as received.

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/sumanmummaneni3/CertificateManager.git
   cd CertificateManager

2. **Build and Install the project**
   ```bash
   % ./gradlew clean build
   % ./gradlew install
   % cd build/installer

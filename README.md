# Home SOC Lab — Phase 2: Vulnerable Target, Custom Detection Rule & Dashboard

This document covers the second phase of a home Security Operations Center (SOC) lab, building on a working **Wazuh SIEM + Suricata IDS** deployment (see Phase 1 documentation). In this phase, a deliberately vulnerable target VM (**Metasploitable2**) is added to the lab, a real vulnerability is investigated end-to-end, a **custom Suricata detection rule** is written and verified, and a **Wazuh dashboard** is built to visualize the results.

## Table of Contents

1. [Lab Topology](#lab-topology)
2. [Part 1 — Isolated Network Setup](#part-1--isolated-network-setup)
3. [Part 2 — Deploying the Vulnerable Target (Metasploitable2)](#part-2--deploying-the-vulnerable-target-metasploitable2)
4. [Part 3 — Reconnaissance Scan](#part-3--reconnaissance-scan)
5. [Part 4 — Investigating the vsftpd 2.3.4 Backdoor](#part-4--investigating-the-vsftpd-234-backdoor)
6. [Part 5 — Writing a Custom Suricata Detection Rule](#part-5--writing-a-custom-suricata-detection-rule)
7. [Part 6 — Building a Suricata Dashboard in Wazuh](#part-6--building-a-suricata-dashboard-in-wazuh)
8. [Troubleshooting Log](#troubleshooting-log)
9. [Key Findings Summary](#key-findings-summary)
10. [Tools Used](#tools-used)

---

## Lab Topology

| Host | Role | IP Address | Network |
|---|---|---|---|
| **jayy** | Ubuntu VM running Wazuh (Docker) + Suricata IDS | `192.168.100.20` (internal) / NAT on `enp0s3` | `soclab-internal` (enp0s8) + NAT (enp0s3) |
| **Metasploitable2** | Deliberately vulnerable Ubuntu 8.04 target | `192.168.100.10` | `soclab-internal` only |

The two VMs communicate **only** over an isolated VirtualBox Internal Network (`soclab-internal`), which has no route to the host's real LAN or the internet. `jayy` keeps a separate NAT adapter for its own internet access (updates, Docker pulls, etc.).

> **Why isolate it:** Metasploitable2 is intentionally full of unpatched, exploitable services. It must never be reachable from an untrusted network.

---

## Part 1 — Isolated Network Setup

### 1.1 Create the internal network (VirtualBox Manager, both VMs)

For **jayy**:
- Settings → Network → Adapter 2 → Enable Network Adapter
- Attached to: `Internal Network`
- Name: `soclab-internal`

For **Metasploitable2**:
- Settings → Network → Adapter 1 → Attached to: `Internal Network`
- Name: `soclab-internal` (must match exactly)

### 1.2 Assign a static IP to Metasploitable2 (persistent)

Metasploitable2 runs old Ubuntu 8.04, which uses the legacy `/etc/network/interfaces` system (not netplan).

```bash
sudo nano /etc/network/interfaces
```

Set the `eth0` block to:

```
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.168.100.10
    netmask 255.255.255.0
```

Apply and verify:

```bash
sudo /etc/init.d/networking restart
ifconfig eth0
```

### 1.3 Assign a static IP to jayy (persistent, via netplan)

jayy uses **netplan** with the **NetworkManager** renderer. First identify the active config file:

```bash
ls /etc/netplan/
sudo cat /etc/netplan/00-installer-config.yaml
```

Edit it:

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Add the `enp0s8` block at the **same indentation level** as the existing `enp0s3` block:

```yaml
network:
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp6: true
      match:
        macaddress: 08:00:29:fe:5c:8d
      set-name: enp0s3
    enp0s8:
      dhcp4: false
      addresses: [192.168.100.20/24]
  version: 2
```

> **YAML tip:** indentation must use spaces, not tabs, and must be consistent — this is the #1 cause of netplan errors.

Apply and verify:

```bash
sudo netplan apply
ip a show enp0s8
```

### 1.4 Confirm connectivity between the two VMs

From jayy:

```bash
ping -c 4 192.168.100.10
```

---

## Part 2 — Deploying the Vulnerable Target (Metasploitable2)

1. **Download** the official Metasploitable2 image (~800 MB ZIP) from the Rapid7-maintained SourceForge project.
2. **Extract** the ZIP — it contains VMware-format files (`.vmx`, `.vmxf`, `.vmdk`, `.vmsd`, `.nvram`). Only the **`.vmdk`** (virtual disk) is needed for VirtualBox.
3. **Create a new VM** in VirtualBox:
   - Name: `Metasploitable2`
   - Type: **Linux**, Distribution: **Ubuntu**, Version: **Ubuntu (32-bit)**
   - Memory: **512 MB**, 1 CPU
   - Hard disk: **"Use an Existing Virtual Hard Disk File"** → select the extracted `.vmdk`
4. **Set networking** to Internal Network `soclab-internal` (see Part 1.1).
5. **Boot the VM.** It boots to a text console (no GUI — this is a stripped-down server image).
6. **Log in** with the default credentials:
   ```
   Username: msfadmin
   Password: msfadmin
   ```
7. Assign the static IP as described in Part 1.2.

---

## Part 3 — Reconnaissance Scan

From jayy, run a service/version detection scan against the target:

```bash
nmap -sV -A 192.168.100.10
```

### Summary of findings

| Port | Service | Notable Issue |
|---|---|---|
| 21 | vsftpd 2.3.4 (FTP) | Anonymous login allowed; **known backdoor in this exact version** |
| 22 | SSH | Old version |
| 23 | Telnet | Unencrypted credentials |
| 25 | SMTP | Open mail relay risk |
| 53 | BIND 9.4.2 (DNS) | Old, vulnerable version |
| 5432 | PostgreSQL | Wide open, no restrictions |
| 5900 | VNC | Remote screen access, no auth hardening |
| 6667 | UnrealIRCd | **Known backdoor** |
| 8180 | Apache Tomcat | Old version |
| — | SMB (Samba) | Guest access allowed, message signing disabled |

This scan itself generated Suricata alerts (`ET SCAN Possible Nmap User-Agent Observed`) — confirming the IDS was watching and logging the reconnaissance activity.

---

## Part 4 — Investigating the vsftpd 2.3.4 Backdoor

### 4.1 Background

vsftpd 2.3.4's source code was compromised by an attacker years ago before being caught and removed from distribution. The backdoored binary: if an FTP username ending in a smiley face `:)` is submitted, it opens a raw root shell on **port 6200**.

### 4.2 Triggering the backdoor (manual, for detection-training purposes)

From jayy:

```bash
telnet 192.168.100.10 21
```

At the FTP prompt, send:

```
USER backdoored:)
```
```
PASS anything
```

Exit telnet: `Ctrl+]`, then `quit`.

### 4.3 Confirming the backdoor opened

```bash
nmap -p 6200 192.168.100.10
```
Result: port `6200` shown as **open**.

### 4.4 Checking what Suricata captured

Total alert count in the log:
```bash
sudo grep -ac '"event_type":"alert"' /var/log/suricata/eve.json
```

Alerts specifically tied to the target IP, broken down by signature:
```bash
sudo grep -a '192.168.100.10' /var/log/suricata/eve.json \
  | grep -a '"event_type":"alert"' \
  | grep -ao '"signature":"[^"]*"' \
  | sort | uniq -c
```

Searching for a specific known signature by text (safer than guessing exact JSON field spacing):
```bash
sudo grep -a -i 'returned root' /var/log/suricata/eve.json
```

### 4.5 Key finding — a detection gap

- **No alert fired** for the actual FTP trigger (`USER backdoored:)`) — the default Suricata ruleset has no signature for this specific backdoor string.
- **An alert DID fire** for the *consequence*: `GPL ATTACK_RESPONSE id check returned root` (signature ID `2100498`) — a generic rule that watches for the text pattern produced when a Unix `id` command returns root-level output, regardless of which vulnerability caused it.

**In plain terms:** the IDS caught the *result* of successful exploitation (a root shell responding), but missed the *attempt* itself. This is a realistic and common detection gap — and exactly what a custom rule can close.

---

## Part 5 — Writing a Custom Suricata Detection Rule

### 5.1 Locate the rules directory

```bash
sudo ls -la /etc/suricata/
sudo grep -n "default-rule-path" /etc/suricata/suricata.yaml
```
Confirmed default rule path: `/var/lib/suricata/rules/`

### 5.2 Create a dedicated local rules file

> **Best practice:** never edit the downloaded `suricata.rules` file directly — `suricata-update` will overwrite it. Custom rules go in their own file.

```bash
sudo nano /var/lib/suricata/rules/local.rules
```

Rule added:

```
alert tcp any any -> any 21 (msg:"LOCAL FTP vsftpd 2.3.4 backdoor trigger detected"; flow:to_server,established; content:"USER "; nocase; content:":)"; distance:0; classtype:trojan-activity; sid:1000001; rev:1;)
```

**Rule breakdown:**

| Part | Meaning |
|---|---|
| `alert tcp any any -> any 21` | Watch TCP traffic to port 21 (FTP), from/to anywhere |
| `flow:to_server,established` | Only inspect established connections, traffic heading to the server |
| `content:"USER "` | Look for the literal FTP username command |
| `nocase` | Case-insensitive match |
| `content:":)"` | Look for the literal backdoor trigger string |
| `distance:0` | The `:)` must appear after `USER ` in the stream |
| `classtype:trojan-activity` | Categorizes the alert as trojan/backdoor-related |
| `sid:1000001` | Unique rule ID — **custom rules must use SID ≥ 1,000,000** to avoid clashing with official rulesets |
| `rev:1` | Revision number (increment on edits) |

### 5.3 Register the rule file in the main config

```bash
sudo grep -n "rule-files" /etc/suricata/suricata.yaml
```

Edit `suricata.yaml` so the `rule-files:` list includes both files, with **matching indentation**:

```yaml
rule-files:
  - suricata.rules
  - local.rules
```

> **Common pitfall hit during this build:** inconsistent indentation between list items under `rule-files:` breaks the YAML parser. Both lines must have identical leading whitespace.

### 5.4 Validate and apply

Test the config before restarting the live service:
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
Look for: `N rule files processed. X rules successfully loaded, 0 rules failed`

Restart the service:
```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```

### 5.5 Verify the rule fires

Re-trigger the backdoor sequence (Part 4.2), then check the plaintext alert feed:
```bash
sudo tail -20 /var/log/suricata/fast.log
```

Result — the custom rule fired successfully:
```
[**] [1:1000001:1] LOCAL FTP vsftpd 2.3.4 backdoor trigger detected [**]
[Classification: A Network Trojan was detected] [Priority: 1]
{TCP} 192.168.100.20:40828 -> 192.168.100.10:21
```

Confirm it's also in the structured JSON log (useful for the SIEM pipeline):
```bash
sudo grep -a '1000001' /var/log/suricata/eve.json
```

**Result:** the exploitation *attempt* is now detected in real time, at the highest priority level, instead of only being inferred after the fact from its consequences.

---

## Part 6 — Building a Suricata Dashboard in Wazuh

### 6.1 Finding the correct field names

Wazuh nests Suricata's alert data under `data.*`. Confirmed via Discover:

| Data point | Field |
|---|---|
| Event type | `data.event_type` |
| Suricata signature ID | `data.alert.signature_id` |
| Signature text | `data.alert.signature` |
| Severity | `data.alert.severity` |
| Source/Dest IP | `data.src_ip` / `data.dest_ip` |
| Application protocol | `data.app_proto` |

A reliable query to isolate all Suricata-originated alerts:
```
data.alert.signature_id:*
```

### 6.2 Panel 1 — Alerts Over Time (Bar Chart)

- Visualize → New Visualization → **Vertical Bar**
- Index pattern: `wazuh-alerts-*`
- Metrics (Y-axis): **Count**
- Buckets (X-axis): **Date Histogram**, field `@timestamp`, interval set **explicitly** (e.g. "Day") rather than left on "Auto" — leaving it on Auto caused an unresolved validation error in this environment
- Search filter: `data.alert.signature_id:*`
- Saved as: `Suricata Alerts Over Time`

### 6.3 Panel 2 — Severity Breakdown (Pie Chart)

- Visualize → New Visualization → **Pie**
- Buckets → Split Slices → Aggregation: **Terms** → Field: `data.alert.severity`
- Order by: **Metric: Count**, Descending
- Saved as: `Suricata Alert Severity Breakdown`

### 6.4 Panel 3 — Top Signatures (Data Table)

- Visualize → New Visualization → **Data Table**
- Buckets → Split Rows → Aggregation: **Terms** → Field: `data.alert.signature` (note: `.keyword` sub-field was not available in this index; plain text field used instead)
- Size: 10, Order by: **Metric: Count**, Descending
- Saved as: `Suricata Top Signatures`

**Result (Top Signatures table):**

| Signature | Count |
|---|---|
| ET SCAN Possible Nmap User-Agent Observed | 57 |
| SURICATA TLS invalid record type | 28 |
| SURICATA Applayer Mismatch protocol both directions | 12 |
| SURICATA Applayer Detect protocol only one direction | 10 |
| SURICATA SMB malformed request dialects | 6 |
| SURICATA STREAM ESTABLISHED packet out of window | 6 |
| SURICATA STREAM ESTABLISHED invalid ack | 5 |
| SURICATA STREAM Packet with invalid ack | 5 |
| SURICATA HTTP unable to match response to request | 2 |
| SURICATA STREAM excessive retransmissions | 2 |

### 6.5 Assembling the dashboard

1. ☰ menu → **Dashboards** → **Create new dashboard**
2. **Add panel** → select all three saved visualizations
3. Arrange/resize panels
4. Save, name: `Suricata IDS Dashboard`
5. **Check "Store time with dashboard"** — this saves the current time range with the dashboard, so it always opens showing the relevant data instead of defaulting to a narrow window that looks empty

---

## Troubleshooting Log

| # | Issue | Root Cause | Fix |
|---|---|---|---|
| 1 | `Error writing /etc/suricata/rules/local.rules: No such file or directory` | Assumed rules directory that didn't exist on this system | Located actual path via `default-rule-path` in `suricata.yaml`: `/var/lib/suricata/rules/` |
| 2 | `rule-files:` YAML errors after edits | Inconsistent indentation between `suricata.rules` and `local.rules` list items | Rewrote both lines with identical (2-space) indentation using `sed` |
| 3 | Custom rule not appearing in `eve.json` grep search | Wrong search approach — searched for `"sid":1000001` which doesn't match the actual JSON structure | Searched by rule message text instead; confirmed correct field is `signature_id` (no `sid` key at top level) |
| 4 | Suricata failing to bind `enp0s8` — `failed to set fanout mode` (recurring for days) | VirtualBox's virtual NIC driver doesn't support AF_PACKET fanout/cluster mode reliably on internal-network-only adapters | Removed `cluster-id`/`cluster-type` from the `enp0s8` interface block in `suricata.yaml`, replaced with `threads: 1` to disable fanout for that interface only |
| 5 | Metasploitable2 IP resets on every reboot | `ifconfig` changes are session-only, not persistent | Set static IP properly via `/etc/network/interfaces` |
| 6 | jayy's `enp0s8` IP resets on every reboot | Same — `ip addr add` is session-only | Set static IP properly via netplan (`00-installer-config.yaml`) |
| 7 | Dashboard bar chart stuck showing single "All docs" bucket | Date Histogram bucket was configured but not applied — needed explicit "Update" click | Located and clicked the Update button in the panel editor |
| 8 | "Minimum Interval" field showing red/invalid despite displaying "Auto" | UI display glitch — the Auto value wasn't actually registered | Manually selected an explicit interval value instead of relying on Auto |
| 9 | "Search error: Unauthorized" after clicking Update | Dashboard session had expired during extended troubleshooting | Re-logged into the Wazuh dashboard |
| 10 | Wazuh field search failures (`location:"..."` returning 0 hits) | Assumed field name from raw JSON didn't match how Wazuh indexes/nests Suricata data | Discovered correct nested field convention (`data.alert.signature_id`, etc.) by testing known values directly in Discover |

---

## Key Findings Summary

1. **Reconnaissance confirmed a wide attack surface** on Metasploitable2 — multiple outdated, misconfigured, or backdoored services.
2. **A real detection gap was identified**: Suricata's default ruleset detected the *consequence* of the vsftpd backdoor (a root shell responding) but not the *exploitation attempt* itself.
3. **A custom detection rule closed that gap**, moving detection from "after the fact" to "at the moment of attack," at the highest priority level.
4. **The full pipeline was validated end-to-end**: Suricata → `eve.json` → Wazuh Agent → Wazuh Manager → Wazuh Indexer → Wazuh Dashboard, including a purpose-built visual dashboard for ongoing monitoring.

---

## Tools Used

| Tool | Purpose |
|---|---|
| **VirtualBox** | Hypervisor hosting both VMs; Internal Network used to isolate the vulnerable target |
| **Ubuntu** (jayy) | Host OS for the SIEM/IDS stack |
| **Metasploitable2** | Deliberately vulnerable Ubuntu 8.04 target VM (Rapid7) |
| **Docker / Docker Compose** | Runs the Wazuh stack (indexer, manager, dashboard) |
| **Wazuh 4.9.0** | SIEM platform — log aggregation, alerting, dashboarding |
| **Suricata 8.0.6** | Network IDS — packet capture, signature-based detection |
| **Wazuh Agent** | Forwards Suricata's log data from jayy into the Wazuh Manager |
| **Nmap** | Reconnaissance / service-version scanning |
| **Telnet** | Manual protocol interaction used to trigger the FTP backdoor for detection testing |
| **netplan** | Persistent network configuration on jayy (Ubuntu, modern) |
| **`/etc/network/interfaces`** | Persistent network configuration on Metasploitable2 (Ubuntu 8.04, legacy) |

---

~This document records a personal training lab exercise conducted entirely within isolated virtual machines for educational purposes.~

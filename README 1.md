# Mirai SSH Honeypot Research — TIR-2026-001

Personal threat intel project. I set up an SSH honeypot using Cowrie and Wazuh on DigitalOcean to learn hands-on how attacks actually work in the wild. Within a few hours of going live it got hit by a Mirai botnet variant that installed a backdoor and dropped a Monero miner.

This repo documents what I found.

---

## What I Caught

A Mirai botnet variant (family: `usble726`) that:
- Brute forced SSH credentials
- Ran a cleanup script to remove competing malware
- Installed a persistent SSH backdoor key using `chattr` to make it undeletable
- Deployed a custom-compiled XMRig Monero miner
- Sent an `auth_ok` beacon back to C2

The whole thing was automated. No human on the other end.

---

## Key IOCs

| Type | Value |
|------|-------|
| SHA256 | `048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7` |
| Attacker IP | `130.12.180.51` |
| ISP / ASN | Virtualine Technologies / AS202412, Aachen, Germany |
| IP Abuse Score | 100% confidence — 3,141 reports (AbuseIPDB) |
| SSH Backdoor Key Comment | `rsa-key-20230629` |
| Beacon String | `auth_ok` (hex: `\x61\x75\x74\x68\x5F\x6F\x6B`) |
| Malware Family | Mirai (`usble726`) |
| Mining Protocol | `stratum+ssl://`, `stratum+tcp://` |
| Mining Algorithm | CryptoNight MoneroV7/V8 |

Full IOC list: [`iocs/iocs.csv`](iocs/iocs.csv)

---

## MITRE ATT&CK

| ID | Technique | Tactic |
|----|-----------|--------|
| T1110.001 | Password Guessing | Credential Access |
| T1021.004 | Remote Services: SSH | Lateral Movement |
| T1059 | Command and Scripting Interpreter | Execution |
| T1098.004 | SSH Authorized Keys | Persistence |
| T1082 | System Information Discovery | Discovery |
| T1070 | Indicator Removal | Defense Evasion |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1496 | Resource Hijacking (Cryptomining) | Impact |
| T1027 | Obfuscated Files or Information (UPX) | Defense Evasion |

---

## Attack Chain

```
1. SSH brute force on port 22
2. chmod +x clean.sh; sh clean.sh; rm -rf clean.sh       # remove competing malware
3. chmod +x setup.sh; sh setup.sh; rm -rf setup.sh       # deploy payload
4. chattr -ia ~/.ssh/authorized_keys                      # remove immutable flag
5. echo "ssh-rsa AAAA...rsa-key-20230629" >> authorized_keys  # install backdoor key
6. chattr +ai ~/.ssh/authorized_keys                      # re-lock file
7. uname -a                                               # fingerprint system
8. echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"           # auth_ok beacon
```

---

## Malware Analysis

The binary captured by Cowrie was a UPX-packed ELF 32-bit executable.

```bash
# Unpack
upx -d malware.bin -o malware_unpacked.bin

# Extract strings
strings malware_unpacked.bin | grep -E "stratum|xmr|pool|ssh"
```

Notable strings found:
- `stratum+ssl://` and `stratum+tcp://` — XMRig mining protocols
- `cryptonight-monerov7` / `cryptonight-monerov8` — mining algorithms
- `ssh-userauth` — SSH spreading capability
- Build path: `/var/build/xmrig` — custom compiled, not a generic download
- Config delivered at runtime — no hardcoded wallet or pool address

VirusTotal result: **Trojan.Mirai / usble726**

Raw strings output: [`analysis/strings_output.txt`](analysis/strings_output.txt)

---

## Detection

Custom Wazuh rules for Cowrie events are in [`iocs/cowrie_rules.xml`](iocs/cowrie_rules.xml).

**Host-based:**
- Alert on `chattr` modifications to `~/.ssh/authorized_keys`
- Monitor for unauthorized keys added to `authorized_keys`
- Alert on UPX-packed ELF binaries written to `/tmp` or home directories

**Network:**
- Block outbound `stratum+ssl://` and `stratum+tcp://` connections
- Alert on SSH brute force patterns (rapid sequential auth attempts)

---

## Infrastructure

| Component | Tool |
|-----------|------|
| Honeypot | Cowrie SSH Honeypot |
| SIEM | Wazuh 4.14.5 |
| Platform | DigitalOcean Droplets |
| OS | Ubuntu 22.04 |

---

## Report

Full threat intel report: [`report/TIR-2026-001_Mirai_SSH_Honeypot.docx`](report/TIR-2026-001_Mirai_SSH_Honeypot.docx)

**TLP: WHITE** — free to share and use.

---

## Notes

This is a personal learning project. I'm transitioning into security intelligence from a telecom background and built this lab to get hands-on experience. Still learning — if you spot something wrong or have feedback feel free to open an issue.

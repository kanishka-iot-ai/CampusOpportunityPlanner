import os
import re
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime

import mysql.connector
from mysql.connector.errors import IntegrityError, DatabaseError, Error
from dotenv import load_dotenv
from flask import g


load_dotenv()


def _row_to_dict(row):
    if row is None:
        return None
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, str) and (k.endswith(('_at', '_date', '_deadline')) or k in ('application_deadline', 'applied_at', 'due_date', 'changed_at', 'created_at', 'updated_at', 'expires_at')):
            try:
                d[k] = datetime.fromisoformat(v.replace('Z', ''))
            except Exception:
                pass
    return d


class SQLiteCursor:
    def __init__(self, cur):
        self._cur = cur
        self.lastrowid = None
        self.rowcount = 0
        self._results = None

    def execute(self, sql, params=()):
        sql_lower = sql.strip().lower()
        if "information_schema.columns" in sql_lower:
            table = params[0] if params else "opportunities"
            self._cur.execute(f'PRAGMA table_info("{table}")')
            cols = self._cur.fetchall()
            self._results = [{
                "COLUMN_NAME": c["name"],
                "DATA_TYPE": c["type"],
                "IS_NULLABLE": "NO" if c["notnull"] else "YES",
                "COLUMN_KEY": "PRI" if c["pk"] else ""
            } for c in cols]
            self.rowcount = len(self._results)
            return self

        if "information_schema.key_column_usage" in sql_lower:
            table = params[0] if params else "opportunities"
            self._cur.execute(f'PRAGMA foreign_key_list("{table}")')
            fks = self._cur.fetchall()
            self._results = [{
                "COLUMN_NAME": fk["from"],
                "REFERENCED_TABLE_NAME": fk["table"],
                "REFERENCED_COLUMN_NAME": fk["to"]
            } for fk in fks]
            self.rowcount = len(self._results)
            return self

        adapted = sql
        adapted = re.sub(r'\s+FOR\s+UPDATE\b', '', adapted, flags=re.IGNORECASE)
        adapted = re.sub(r'ON\s+DUPLICATE\s+KEY\s+UPDATE\s+[^\s]+', 'ON CONFLICT(bucket_key) DO NOTHING', adapted, flags=re.IGNORECASE)
        adapted = adapted.replace('%s', '?')

        try:
            self._cur.execute(adapted, params)
            self.lastrowid = self._cur.lastrowid
            self.rowcount = self._cur.rowcount
            self._results = None
            return self
        except sqlite3.IntegrityError as e:
            raise IntegrityError(str(e)) from e
        except sqlite3.Error as e:
            raise DatabaseError(str(e)) from e

    def fetchone(self):
        if self._results is not None:
            return self._results.pop(0) if self._results else None
        row = self._cur.fetchone()
        return _row_to_dict(row)

    def fetchall(self):
        if self._results is not None:
            res = self._results
            self._results = []
            return res
        return [_row_to_dict(r) for r in self._cur.fetchall()]

    def close(self):
        self._cur.close()


class SQLiteWrapper:
    def __init__(self, conn):
        self._conn = conn
        self.is_sqlite = True

    def cursor(self, dictionary=True):
        return SQLiteCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def get_sqlite_connection():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    bundled_db = os.path.join(base_dir, "database", "app.db")
    is_vercel = bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV"))
    
    # In Vercel or read-only container environments, use /tmp
    target_db = "/tmp/campus_opportunity_planner.db" if (is_vercel and os.path.exists("/tmp")) else bundled_db
    if target_db != bundled_db and (not os.path.exists(target_db) or os.path.getsize(target_db) == 0):
        if os.path.exists(bundled_db):
            shutil.copyfile(bundled_db, target_db)
            
    conn = sqlite3.connect(target_db, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.create_function("NOW", 0, lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    conn.create_function("IF", 3, lambda cond, a, b: a if cond else b)
    conn.create_function("DATABASE", 0, lambda: "campus_opportunity_planner")
    return SQLiteWrapper(conn)


def get_db_connection():
    db_host = (os.getenv("DB_HOST") or "").strip()
    is_vercel = bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV"))

    # If DB_HOST is sqlite or explicitly empty, use SQLite fallback
    if db_host.lower() == "sqlite":
        return get_sqlite_connection()

    # On Vercel, localhost/127.0.0.1 is unreachable
    if is_vercel and db_host in ("localhost", "127.0.0.1", ""):
        return get_sqlite_connection()

    if db_host:
        try:
            connect_kwargs = {
                "host": db_host,
                "port": int(os.getenv("DB_PORT", "3306")),
                "user": os.getenv("DB_USER"),
                "password": os.getenv("DB_PASSWORD"),
                "database": os.getenv("DB_NAME"),
                "connection_timeout": int(os.getenv("DB_TIMEOUT", "3" if is_vercel else "10")),
                "autocommit": False,
            }
            ssl_disabled = os.getenv("DB_SSL_DISABLED", "").strip().lower() in ("true", "1", "yes")
            if ssl_disabled:
                connect_kwargs["ssl_disabled"] = True
            else:
                ssl_ca = os.getenv("DB_SSL_CA", "").strip()
                if ssl_ca and os.path.exists(ssl_ca):
                    connect_kwargs["ssl_ca"] = ssl_ca
                if os.getenv("DB_SSL_VERIFY_CERT", "").strip().lower() in ("false", "0", "no"):
                    connect_kwargs["ssl_verify_cert"] = False
                    connect_kwargs["ssl_verify_identity"] = False

            connection = mysql.connector.connect(**connect_kwargs)
            cursor = connection.cursor()
            try:
                cursor.execute('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED')
            except Exception:
                connection.close()
                raise
            finally:
                cursor.close()
            return connection
        except Exception:
            # Fallback to SQLite so the app works seamlessly when MySQL is unreachable or on Vercel
            base_dir = os.path.dirname(os.path.abspath(__file__))
            bundled_db = os.path.join(base_dir, "database", "app.db")
            if is_vercel or not db_host or os.path.exists(bundled_db):
                return get_sqlite_connection()
            raise

    return get_sqlite_connection()


def get_db():
    if 'db' not in g:
        g.db = get_db_connection()
    return g.db


def query(sql, params=(), one=False):
    cursor = get_db().cursor(dictionary=True)
    try:
        cursor.execute(sql, params)
        return cursor.fetchone() if one else cursor.fetchall()
    finally:
        cursor.close()


def execute(sql, params=()):
    cursor = get_db().cursor()
    try:
        cursor.execute(sql, params)
        return cursor.lastrowid
    finally:
        cursor.close()


@contextmanager
def transaction():
    db = get_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def close_db(error=None):
    db = g.pop('db', None)
    if db:
        try:
            db.rollback()
        finally:
            db.close()

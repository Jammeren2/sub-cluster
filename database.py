"""Shared PostgreSQL backend; SQLite remains the explicit legacy/local mode.

The SQL compatibility layer covers this project's small SQLite SQL vocabulary.
Transactions use scoped advisory locks for existing read/modify/write operations.
No fallback to local data is allowed when DATABASE_URL is configured.
"""
from contextlib import contextmanager
import atexit
import hashlib
import time
import os
import re
import sqlite3
import sys
import threading

DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
class DatabaseUnavailable(RuntimeError):
    pass


_pools = {}
_pool_lock = threading.Lock()


def schema_for(node):
    return 'checker_' + hashlib.sha256(node.encode()).hexdigest()[:24]


def shared():
    return bool(DATABASE_URL)


def pool():
    import psycopg
    from psycopg_pool import ConnectionPool
    with _pool_lock:
        if DATABASE_URL not in _pools:
            # autocommit prevents idle read transactions; writes use explicit blocks.
            _pools[DATABASE_URL] = ConnectionPool(DATABASE_URL, min_size=1, max_size=12,
                timeout=10, open=True, kwargs={'autocommit': True, 'connect_timeout': 5,
                                   'application_name': 'sub-cluster', 'target_session_attrs': 'read-write'},
                check=ConnectionPool.check_connection)
        return _pools[DATABASE_URL]


def lock_id(name):
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], 'big', signed=True)


class Row(dict):
    def __getitem__(self, key):
        return list(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


class Result:
    def __init__(self, rows=(), names=(), mapped=False, rowcount=-1):
        self.rows = [Row(zip(names, r)) if mapped else r for r in rows]
        self.rowcount = rowcount
        self.offset = 0
    def fetchone(self):
        if self.offset == len(self.rows):
            return None
        row = self.rows[self.offset]
        self.offset += 1
        return row
    def fetchall(self):
        rows = self.rows[self.offset:]
        self.offset = len(self.rows)
        return rows
    def __iter__(self):
        return iter(self.fetchall())


def translate(sql):
    # All double-quoted tokens in the existing application queries are literals.
    sql = re.sub(r'"([^"\n]*)"', lambda m: "'" + m[1].replace("'", "''") + "'", sql)
    sql = re.sub(r'\bREAL\b', 'DOUBLE PRECISION', sql)
    sql = sql.replace('slug=? COLLATE NOCASE', 'lower(slug)=lower(?)')
    sql = sql.replace('slug COLLATE NOCASE', 'lower(slug)')
    sql = sql.replace('cnt=cnt+1', 'cnt=device_seen.cnt+1')
    sql = sql.replace('count=count+1', 'count=personal_limits.count+1')
    sql = sql.replace('INSERT OR REPLACE INTO checked_peer_snapshots VALUES(?,?)',
                      'INSERT INTO checked_peer_snapshots VALUES(?,?) ON CONFLICT(node) DO UPDATE SET stamp=excluded.stamp')
    if sql.startswith('CREATE TEMP TABLE current_keys'):
        sql += ' ON COMMIT DROP'
    return sql.replace('?', '%s')


class Connection:
    def __init__(self, raw, schema='public', scope='personal'):
        self.raw, self.schema, self.scope = raw, schema, scope
        self.row_factory = None
    def execute(self, sql, params=()):
        if sql == 'BEGIN IMMEDIATE':
            return self.execute('SELECT pg_advisory_xact_lock(?)', (lock_id(self.scope),))
        if sql.startswith('PRAGMA journal_mode'):
            return Result()
        match = re.fullmatch(r'PRAGMA table_info\((\w+)\)', sql)
        if match:
            rows = self.raw.execute('SELECT ordinal_position,column_name FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position', (self.schema, match[1])).fetchall()
            return Result(rows)
        cursor = self.raw.execute(translate(sql), params)
        names = [d.name for d in cursor.description] if cursor.description else []
        return Result(cursor.fetchall() if names else [], names, self.row_factory is not None, cursor.rowcount)
    def executemany(self, sql, rows):
        with self.raw.cursor() as cursor:
            cursor.executemany(translate(sql), rows)
    def commit(self):
        pass  # outer transaction context owns commit, including nested Store calls
    def close(self):
        pass  # connection belongs to the pool


@contextmanager
def connect(db_file, *, schema='public', scope='personal', mapped=False):
    if not shared():
        db = sqlite3.connect(db_file, timeout=15)
        if mapped:
            db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()
        return
    import psycopg
    from psycopg_pool import PoolTimeout
    try:
        with pool().connection() as raw, raw.transaction():
            raw.execute('SET LOCAL synchronous_commit = on')
            raw.execute('SET LOCAL statement_timeout = 15000')
            raw.execute('SET LOCAL lock_timeout = 10000')
            raw.execute('SET LOCAL search_path TO ' + schema + ', public')
            db = Connection(raw, schema, scope)
            db.row_factory = Row if mapped else None
            yield db
    except (psycopg.OperationalError, psycopg.InterfaceError, PoolTimeout) as exc:
        raise DatabaseUnavailable('Shared database temporarily unavailable') from exc
    except psycopg.IntegrityError as exc:
        raise sqlite3.IntegrityError('Shared database constraint violation') from exc


class StoreConnection:
    """Thread-local transaction handle behind Store's existing connection API."""
    def __init__(self):
        self.local = threading.local()
    def execute(self, sql, params=()):
        return self.local.db.execute(sql, params)
    def commit(self):
        pass
    def close(self):
        pass


class StoreLock:
    def __init__(self, connection):
        self.connection = connection
        self.local = threading.local()
    def __enter__(self):
        depth = getattr(self.local, 'depth', 0)
        if depth == 0:
            context = connect('', scope='store')
            db = context.__enter__()
            try:
                db.execute('BEGIN IMMEDIATE')
            except BaseException:
                context.__exit__(*sys.exc_info())
                raise
            self.local.context = context
            self.connection.local.db = db
        self.local.depth = depth + 1
        return self
    def __exit__(self, *exc):
        self.local.depth -= 1
        if not self.local.depth:
            try:
                return self.local.context.__exit__(*exc)
            finally:
                del self.connection.local.db


def initialize_checker(node):
    schema = schema_for(node)
    with connect('', scope='checker-schema') as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('CREATE SCHEMA IF NOT EXISTS ' + schema)
        db.execute('CREATE TABLE IF NOT EXISTS source_observations(node TEXT,url TEXT,key TEXT,link TEXT,checked REAL,country TEXT,PRIMARY KEY(node,url,key))')
        db.execute('CREATE INDEX IF NOT EXISTS source_observations_url ON source_observations(url,checked)')
    return schema


def session_put(token, exp, csrf):
    with connect('', scope='sessions') as db:
        db.execute('INSERT INTO admin_sessions(token_hash,exp,csrf) VALUES(?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), exp, csrf))
        db.execute('DELETE FROM admin_sessions WHERE exp<?', (time.time(),))


def session_get(token):
    with connect('') as db:
        row = db.execute('SELECT exp,csrf FROM admin_sessions WHERE token_hash=? AND exp>?', (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
    return {'exp': row[0], 'csrf': row[1]} if row else None


def session_delete(token):
    with connect('') as db:
        db.execute('DELETE FROM admin_sessions WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),))


def close_pools():
    for value in _pools.values():
        value.close()
    _pools.clear()


atexit.register(close_pools)


def login_blocked(ip):
    with connect('') as db:
        row = db.execute('SELECT locked_until FROM admin_login_limits WHERE ip_hash=?', (hashlib.sha256(ip.encode()).hexdigest(),)).fetchone()
    return max(0, int(row[0] - time.time())) if row else 0


def login_register(ip, success, maximum, seconds):
    key = hashlib.sha256(ip.encode()).hexdigest()
    with connect('', scope='login-limits') as db:
        db.execute('BEGIN IMMEDIATE')
        now = time.time()
        db.execute('DELETE FROM admin_login_limits WHERE touched<?', (now - max(86400, seconds),))
        if success:
            db.execute('DELETE FROM admin_login_limits WHERE ip_hash=?', (key,))
            return
        row = db.execute('SELECT failures,locked_until FROM admin_login_limits WHERE ip_hash=?', (key,)).fetchone()
        failures = (row[0] if row else 0) + 1
        locked_until = row[1] if row else 0
        if failures >= maximum:
            failures, locked_until = 0, now + seconds
        db.execute('INSERT INTO admin_login_limits VALUES(?,?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until,touched=excluded.touched', (key,failures,locked_until,now))

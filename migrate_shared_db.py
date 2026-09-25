#!/usr/bin/env python3
"""One-time, atomic import of one stopped node's SQLite snapshot into PostgreSQL."""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import time

import database

TABLES = ('kv', 'device_seen', 'personal_links', 'personal_limits', 'checked_sources', 'checked_links')


def read_snapshot(path):
    # SQLite reads the WAL too; do not copy a live .db file without its WAL.
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return {name: sorted([dict(r) for r in db.execute('SELECT * FROM ' + name)], key=lambda row: json.dumps(row, sort_keys=True)) if name in tables else [] for name in TABLES}


def import_snapshot(path, node, authoritative=False):
    if not database.shared():
        raise ValueError('Configure DATABASE_URL first')
    import store
    import personal
    import source_checks
    data = read_snapshot(path)
    digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    target = store.Store(origin=node)
    personal.Registry('unused')
    checker = source_checks.Checker('unused', target)
    with database.connect('', scope='store', mapped=True) as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('SELECT pg_advisory_xact_lock(?)', (database.lock_id('personal'),))
        db.execute('SELECT pg_advisory_xact_lock(?)', (database.lock_id('checker:' + node),))
        db.execute('CREATE TABLE IF NOT EXISTS sqlite_imports(node TEXT PRIMARY KEY,digest TEXT NOT NULL,imported REAL NOT NULL)')
        previous = db.execute('SELECT digest FROM sqlite_imports WHERE node=?', (node,)).fetchone()
        if previous:
            if previous['digest'] != digest:
                raise ValueError('This node was already imported from a different snapshot; refusing duplicate counters')
            return 'already imported'
        docs = {r['key']: r for r in data['kv']}
        if authoritative:
            for key in ('config', 'failover'):
                if key not in docs:
                    raise ValueError('Authoritative snapshot is missing ' + key)
                old = db.execute('SELECT version FROM kv WHERE key=?', (key,)).fetchone()
                if old and old['version'] != 0:
                    raise ValueError('Shared configuration is already initialized; refusing overwrite')
                row = docs[key]
                db.execute('UPDATE kv SET data=?,version=?,updated_at=?,origin=? WHERE key=?',
                           (row['data'], max(1, row['version']), row['updated_at'], row['origin'], key))
        if 'members' in docs:
            current = db.execute("SELECT data FROM kv WHERE key='members'").fetchone()
            members = json.loads(current['data'])
            version = lambda r: (r.get('_v', 0), r.get('_t', 0), r.get('_o', ''))
            for nid, row in json.loads(docs['members']['data']).get('nodes', {}).items():
                old = members.setdefault('nodes', {}).get(nid)
                if old is None or version(row) > version(old):
                    members['nodes'][nid] = row
            db.execute("UPDATE kv SET data=?,version=version+1,updated_at=?,origin=? WHERE key='members'", (json.dumps(members), time.time(), node))
        for row in data['personal_links']:
            row = {**row, 'contact': row.get('contact', '')}
            existing = db.execute('SELECT * FROM personal_links WHERE route=? AND slug=? COLLATE NOCASE', (row['route'], row['slug'])).fetchall()
            if existing:
                if len(existing) != 1 or any(existing[0].get(k) != v for k, v in row.items()):
                    raise ValueError('Conflicting personal link; resolve snapshots before migration')
                continue
            fields = ('route','slug','name','selected','manage_hash','device_hash','created','contact')
            db.execute('INSERT INTO personal_links(' + ','.join(fields) + ') VALUES(' + ','.join('?' for _ in fields) + ')', tuple(row[k] for k in fields))
        for row in data['personal_limits']:
            db.execute('INSERT INTO personal_limits(bucket,since,count) VALUES(?,?,?) ON CONFLICT(bucket) DO UPDATE SET since=GREATEST(personal_limits.since,excluded.since),count=personal_limits.count+excluded.count', (row['bucket'], row['since'], row['count']))
        for row in data['device_seen']:
            old = db.execute('SELECT * FROM device_seen WHERE route_id=? AND device=?', (row['route_id'], row['device'])).fetchone()
            merged = dict(old or {})
            if not old or (row['last_ts'] or 0) >= (old['last_ts'] or 0):
                merged.update(row)
            merged['cnt'] = (old['cnt'] if old else 0) + row['cnt']
            merged['first_ts'] = min(x for x in (row['first_ts'], old['first_ts'] if old else None) if x is not None) if row['first_ts'] is not None or old and old['first_ts'] is not None else None
            merged['node_ids'] = json.dumps(sorted(set(json.loads(old['node_ids']) if old else []) | {node}))
            fields = ('route_id','device','hwid','model','app','ip','cnt','first_ts','last_ts','personal_name','personal_contact','node_ids')
            values = [merged.get(k, '' if k in ('personal_name','personal_contact') else None) for k in fields]
            db.execute('INSERT INTO device_seen(' + ','.join(fields) + ') VALUES(' + ','.join('?' for _ in fields) + ') ON CONFLICT(route_id,device) DO UPDATE SET ' + ','.join(k+'=excluded.'+k for k in fields[2:]), values)
        for table in ('checked_sources', 'checked_links'):
            for row in data[table]:
                fields = ('url','refreshed','error') if table == 'checked_sources' else ('url','key','link','position','checked','state','country','exit_ip','lease_until')
                values = [0 if k == 'lease_until' else row[k] for k in fields]
                db.execute('INSERT INTO ' + checker.schema + '.' + table + '(' + ','.join(fields) + ') VALUES(' + ','.join('?' for _ in fields) + ')', values)
                if table == 'checked_links' and row['state'] == 'ok':
                    db.execute('INSERT INTO source_observations(node,url,key,link,checked,country) VALUES(?,?,?,?,?,?)', (node,row['url'],row['key'],row['link'],row['checked'],row['country']))
        db.execute('INSERT INTO sqlite_imports VALUES(?,?,?)', (node,digest,time.time()))
    return 'imported'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sqlite', required=True)
    parser.add_argument('--node', required=True, help='Original NODE_ID of this snapshot')
    parser.add_argument('--authoritative-config', action='store_true', help='Use routes/settings from this snapshot; exactly one node')
    parser.add_argument('--dry-run', action='store_true', help='Read-only inventory; does not connect to PostgreSQL')
    args = parser.parse_args()
    if args.dry_run:
        print(json.dumps({name: len(rows) for name, rows in read_snapshot(args.sqlite).items()}))
    else:
        print(import_snapshot(args.sqlite, args.node, args.authoritative_config))


if __name__ == '__main__':
    main()

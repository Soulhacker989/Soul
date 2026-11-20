import os, json, time, secrets, hashlib, hmac, sqlite3, re
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("PANEL_DB", os.path.join(APP_DIR, "panel.sqlite3"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "86400"))
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024


def now_ms(): return int(time.time() * 1000)
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=20)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        if exc: conn.rollback()
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS keys (
      code TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', createdAt INTEGER NOT NULL,
      expiresAt INTEGER NOT NULL DEFAULT 0, maxDevices INTEGER NOT NULL DEFAULT 1,
      off INTEGER NOT NULL DEFAULT 0, price INTEGER NOT NULL DEFAULT 0,
      script TEXT NOT NULL DEFAULT 'main', by TEXT NOT NULL DEFAULT '',
      devices TEXT NOT NULL DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS scripts (
      name TEXT PRIMARY KEY, src TEXT NOT NULL, updated INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY, code TEXT NOT NULL, hwid TEXT NOT NULL,
      created INTEGER NOT NULL, last_seen INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY(code) REFERENCES keys(code) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS reseller_tokens (
      token TEXT PRIMARY KEY, rid TEXT NOT NULL, created INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_code ON sessions(code);
    ''')
    # Empty starter script; replace it with a Lua file using the panel editor.
    conn.execute("INSERT OR IGNORE INTO scripts(name,src,updated) VALUES('main','-- Add your authorized Lua script in the panel editor.\\n',?)", (now_ms(),))
    conn.commit(); conn.close()
init_db()

def jerr(message, status=400): return jsonify(ok=False, err=message), status
def parse_json():
    data=request.get_json(silent=True)
    return data if isinstance(data, dict) else {}
def admin_ok():
    token=request.headers.get('X-Admin-Token','')
    return bool(ADMIN_TOKEN) and hmac.compare_digest(token, ADMIN_TOKEN)
def reseller_token(): return request.headers.get('X-Rs-Token','')
def get_reseller(rid):
    row=db().execute("SELECT v FROM meta WHERE k='resellers'").fetchone()
    try: arr=json.loads(row['v']) if row else []
    except Exception: arr=[]
    if isinstance(arr, str):
        try: arr=json.loads(arr)
        except Exception: arr=[]
    return next((r for r in arr if str(r.get('id',''))==str(rid)), None)
def reseller_auth():
    tok=reseller_token()
    if not tok: return None
    row=db().execute('SELECT rid FROM reseller_tokens WHERE token=?', (tok,)).fetchone()
    if not row: return None
    return get_reseller(row['rid'])
def require_admin(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not admin_ok(): return jerr('ADMIN_AUTH_REQUIRED',401)
        return fn(*args, **kwargs)
    return wrapped
def require_reseller(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        r=reseller_auth()
        if not r: return jerr('RESELLER_AUTH_REQUIRED',401)
        return fn(r,*args, **kwargs)
    return wrapped

def key_obj(row):
    d=dict(row); d['off']=bool(d.get('off')); d['devices']=json.loads(d.get('devices') or '[]'); return d
def all_keys(): return [key_obj(x) for x in db().execute('SELECT * FROM keys ORDER BY createdAt DESC').fetchall()]
def get_meta():
    out={}
    for r in db().execute('SELECT k,v FROM meta').fetchall():
        try: out[r['k']]=json.loads(r['v'])
        except Exception: out[r['k']]=r['v']
    return out
def set_meta(meta):
    if not isinstance(meta,dict): return
    conn=db()
    for k,v in meta.items():
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',str(k)): continue
        conn.execute('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',(str(k),json.dumps(v,separators=(',',':'))))

def upsert_key(k, by_override=None):
    code=str(k.get('code','')).strip()
    if not code or len(code)>160: raise ValueError('INVALID_KEY_CODE')
    name=str(k.get('name',''))[:160]
    created=int(k.get('createdAt') or now_ms())
    expires=int(k.get('expiresAt') or 0)
    maxdev=max(1,min(100,int(k.get('maxDevices') or 1)))
    off=1 if k.get('off') else 0
    price=max(0,min(10**9,int(k.get('price') or 0)))
    script=str(k.get('script') or 'main')[:120]
    by=str(by_override if by_override is not None else k.get('by',''))[:160]
    conn=db()
    old=conn.execute('SELECT devices FROM keys WHERE code=?',(code,)).fetchone()
    devices=old['devices'] if old else '[]'
    conn.execute('''INSERT INTO keys(code,name,createdAt,expiresAt,maxDevices,off,price,script,by,devices)
    VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(code) DO UPDATE SET name=excluded.name,expiresAt=excluded.expiresAt,
    maxDevices=excluded.maxDevices,off=excluded.off,price=excluded.price,script=excluded.script,by=excluded.by''',
    (code,name,created,expires,maxdev,off,price,script,by,devices))

def valid_key(code):
    row=db().execute('SELECT * FROM keys WHERE code=?',(code,)).fetchone()
    if not row: return None,'INVALID_KEY'
    k=key_obj(row)
    if k['off']: return None,'KEY_DISABLED'
    if k['expiresAt'] and k['expiresAt'] < now_ms(): return None,'KEY_EXPIRED'
    return k,None

@app.get('/')
def home(): return send_from_directory(os.path.join(APP_DIR,'templates'),'index.html')
@app.get('/api/ping')
def ping():
    token=request.headers.get('X-Admin-Token','')
    return jsonify(ok=True, admin=bool(ADMIN_TOKEN) and hmac.compare_digest(token,ADMIN_TOKEN), service='RennMatrix License API')

@app.post('/api/auth')
def auth():
    d=parse_json(); code=str(d.get('key','')).strip(); hwid=str(d.get('hwid','')).strip()
    if not code or not hwid: return jerr('MISSING_KEY_OR_HWID',400)
    if len(hwid)>256: return jerr('INVALID_HWID',400)
    k,err=valid_key(code)
    if err: return jerr(err,403)
    conn=db(); devices=k['devices']
    # Device list is stored as stable IDs; don't expose unrelated device data.
    if hwid not in devices:
        if len(devices)>=k['maxDevices']: return jerr('DEVICE_LIMIT_REACHED',403)
        devices.append(hwid)
        conn.execute('UPDATE keys SET devices=? WHERE code=?',(json.dumps(devices),code))
    token=secrets.token_urlsafe(32); ts=now_ms()
    conn.execute('INSERT INTO sessions(token,code,hwid,created,last_seen,active) VALUES(?,?,?,?,?,1)',(token,code,hwid,ts,ts)); conn.commit()
    return jsonify(ok=True,token=token,expiresAt=k['expiresAt'],script=k['script'])

@app.post('/api/heartbeat')
def heartbeat():
    d=parse_json(); tok=str(d.get('sess') or d.get('token') or '').strip()
    if not tok: return jerr('MISSING_SESSION',401)
    row=db().execute('SELECT s.*,k.off,k.expiresAt FROM sessions s JOIN keys k ON k.code=s.code WHERE s.token=? AND s.active=1',(tok,)).fetchone()
    if not row: return jerr('INVALID_SESSION',401)
    if row['off'] or (row['expiresAt'] and row['expiresAt']<now_ms()):
        db().execute('UPDATE sessions SET active=0 WHERE token=?',(tok,)); db().commit(); return jerr('LICENSE_INACTIVE',403)
    if now_ms()-row['created'] > SESSION_TTL*1000:
        db().execute('UPDATE sessions SET active=0 WHERE token=?',(tok,)); db().commit(); return jerr('SESSION_EXPIRED',401)
    db().execute('UPDATE sessions SET last_seen=? WHERE token=?',(now_ms(),tok)); db().commit()
    return jsonify(ok=True,alive=True)

def token_from_request():
    authh=request.headers.get('Authorization','')
    if authh.lower().startswith('bearer '): return authh[7:].strip()
    d=parse_json(); return str(d.get('token') or '').strip()
@app.route('/api/payload',methods=['GET','POST'])
def payload():
    tok=token_from_request()
    if not tok: return jerr('MISSING_TOKEN',401)
    row=db().execute('''SELECT s.code,s.hwid,k.off,k.expiresAt,k.script,k.devices FROM sessions s JOIN keys k ON k.code=s.code WHERE s.token=? AND s.active=1''',(tok,)).fetchone()
    if not row: return jerr('INVALID_SESSION',401)
    if row['off'] or (row['expiresAt'] and row['expiresAt']<now_ms()): return jerr('LICENSE_INACTIVE',403)
    if row['hwid'] not in json.loads(row['devices'] or '[]'): return jerr('DEVICE_NOT_REGISTERED',403)
    script=db().execute('SELECT src FROM scripts WHERE name=?',(row['script'],)).fetchone()
    if not script: return jerr('SCRIPT_NOT_FOUND',404)
    db().execute('UPDATE sessions SET last_seen=? WHERE token=?',(now_ms(),tok)); db().commit()
    # Plain Lua source is returned only after server-side license/session checks.
    return app.response_class(script['src'],mimetype='text/plain; charset=utf-8')

@app.get('/api/admin/state')
@require_admin
def admin_state():
    scripts=[dict(name=r['name'],updated=r['updated'],size=len(r['src'])) for r in db().execute('SELECT name,updated,src FROM scripts ORDER BY name')]
    return jsonify(ok=True,keys=all_keys(),meta=get_meta(),scripts=scripts)
@app.post('/api/admin/key')
@require_admin
def admin_key_create():
    try: upsert_key(parse_json()); db().commit()
    except (ValueError,TypeError) as e: return jerr(str(e),400)
    return jsonify(ok=True,key=key_obj(db().execute('SELECT * FROM keys WHERE code=?',(str(parse_json().get('code','')).strip(),)).fetchone()))
@app.patch('/api/admin/key/<path:code>')
@require_admin
def admin_key_patch(code):
    d=parse_json(); row=db().execute('SELECT * FROM keys WHERE code=?',(code,)).fetchone()
    if not row: return jerr('KEY_NOT_FOUND',404)
    k=key_obj(row); k.update(d); k['code']=code
    try: upsert_key(k); db().commit()
    except (ValueError,TypeError) as e: return jerr(str(e),400)
    return jsonify(ok=True)
@app.delete('/api/admin/key/<path:code>')
@require_admin
def admin_key_delete(code):
    db().execute('DELETE FROM keys WHERE code=?',(code,)); db().commit(); return jsonify(ok=True)
@app.post('/api/admin/sync')
@require_admin
def admin_sync():
    d=parse_json(); conn=db()
    keys=d.get('keys')
    if isinstance(keys,list):
        incoming=set()
        for k in keys:
            try: upsert_key(k); incoming.add(str(k.get('code','')).strip())
            except (ValueError,TypeError): continue
        # This endpoint is intentionally a replace operation because the panel labels it PUSH/REPLACE.
        for row in conn.execute('SELECT code FROM keys').fetchall():
            if row['code'] not in incoming: conn.execute('DELETE FROM keys WHERE code=?',(row['code'],))
    set_meta(d.get('meta') or {})
    resets=d.get('resetDevices') or []
    for code in resets:
        conn.execute("UPDATE keys SET devices='[]' WHERE code=?",(str(code),))
    conn.commit()
    return jsonify(ok=True,keys=conn.execute('SELECT COUNT(*) FROM keys').fetchone()[0],devices={k['code']:k['devices'] for k in all_keys()})
@app.post('/api/admin/meta')
@require_admin
def admin_meta():
    set_meta(parse_json().get('meta') or {}); db().commit(); return jsonify(ok=True)
@app.route('/api/admin/script/<path:name>',methods=['GET','PUT','DELETE'])
@require_admin
def admin_script(name):
    name=name.removesuffix('.lua')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,120}',name): return jerr('INVALID_SCRIPT_NAME',400)
    conn=db()
    if request.method=='GET':
        r=conn.execute('SELECT name,src,updated FROM scripts WHERE name=?',(name,)).fetchone()
        return jsonify(ok=True,name=name,src=r['src'],updated=r['updated']) if r else jerr('SCRIPT_NOT_FOUND',404)
    if request.method=='DELETE':
        conn.execute('DELETE FROM scripts WHERE name=?',(name,)); conn.commit(); return jsonify(ok=True)
    src=parse_json().get('src')
    if not isinstance(src,str): return jerr('SRC_MUST_BE_STRING',400)
    if len(src)>5*1024*1024: return jerr('SCRIPT_TOO_LARGE',413)
    conn.execute('INSERT INTO scripts(name,src,updated) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET src=excluded.src,updated=excluded.updated',(name,src,now_ms()))
    conn.commit(); return jsonify(ok=True,name=name,updated=now_ms())

@app.post('/api/rs/login')
def reseller_login():
    d=parse_json(); user=str(d.get('user','')).strip().lower(); password=str(d.get('pass',''))
    row=db().execute("SELECT v FROM meta WHERE k='resellers'").fetchone()
    try: arr=json.loads(row['v']) if row else []
    except Exception: arr=[]
    if isinstance(arr, str):
        try: arr=json.loads(arr)
        except Exception: arr=[]
    r=next((x for x in arr if str(x.get('user','')).lower()==user and hmac.compare_digest(str(x.get('pass','')),password)),None)
    if not r: return jerr('INVALID_RESELLER_CREDENTIALS',401)
    token=secrets.token_urlsafe(32); db().execute('INSERT INTO reseller_tokens(token,rid,created) VALUES(?,?,?)',(token,str(r.get('id','')),now_ms())); db().commit()
    return jsonify(ok=True,rtoken=token,rid=r.get('id',''),name=r.get('name','RESELLER'),coins=int(r.get('coins') or 0))
@app.get('/api/rs/state')
@require_reseller
def reseller_state(r):
    keys=[k for k in all_keys() if str(k.get('by',''))==str(r.get('id',''))]
    return jsonify(ok=True,keys=keys,meta={'coins':r.get('coins',0),'rate':0,'spent':0},scripts=[])
@app.post('/api/rs/key')
@require_reseller
def reseller_create_key(r):
    d=parse_json(); code=str(d.get('code','')).strip()
    if not code: return jerr('INVALID_KEY_CODE',400)
    if db().execute('SELECT 1 FROM keys WHERE code=?',(code,)).fetchone(): return jerr('KEY_EXISTS',409)
    try: upsert_key(d,by_override=str(r.get('id',''))); db().commit()
    except (ValueError,TypeError) as e: return jerr(str(e),400)
    return jsonify(ok=True,coins=int(r.get('coins') or 0))

@app.errorhandler(413)
def too_large(e): return jerr('REQUEST_TOO_LARGE',413)
@app.errorhandler(500)
def server_error(e):
    app.logger.exception('Unhandled server error')
    return jerr('INTERNAL_SERVER_ERROR',500)

if __name__=='__main__':
    if not ADMIN_TOKEN:
        print('WARNING: Set ADMIN_TOKEN before exposing this server publicly.')
    app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')),debug=False)

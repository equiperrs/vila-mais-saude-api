"""Vila+Saúde: demonstrador acadêmico com API, SQLite e sessões por cookie.
NÃO é homologado para dados de pacientes reais.
"""
import os, json, sqlite3, secrets, hashlib, hmac, re, time
from pathlib import Path
from datetime import date, datetime, timedelta
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DB = Path(os.getenv('VILA_DB', str(ROOT / 'vila.sqlite3')))
HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', '8080'))
SECURE_COOKIES = os.getenv('COOKIE_SECURE', '0') == '1'
MAX_BODY = 16000
SESSIONS = {}  # reinicia com o processo; dados do sistema ficam no SQLite
ATTEMPTS = {}
SERVICES = ['Clínico geral', 'Odontologia', 'Enfermagem']


def db():
    c = sqlite3.connect(DB, timeout=8)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON')
    c.execute('PRAGMA busy_timeout = 8000')
    return c


def pw_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 260000)
    return salt.hex() + ':' + hashed.hex()


def pw_check(password, stored):
    try:
        salt, digest = stored.split(':')
        return hmac.compare_digest(pw_hash(password, bytes.fromhex(salt)).split(':')[1], digest)
    except (ValueError, AttributeError):
        return False


def init():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, cpf TEXT UNIQUE,
          birth TEXT, sus TEXT UNIQUE, phone TEXT, email TEXT NOT NULL UNIQUE,
          password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'patient', created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS slots (
          id INTEGER PRIMARY KEY, service TEXT NOT NULL, day TEXT NOT NULL,
          hour TEXT NOT NULL, capacity INTEGER NOT NULL DEFAULT 4,
          UNIQUE(service, day, hour)
        );
        CREATE TABLE IF NOT EXISTS bookings (
          id INTEGER PRIMARY KEY, patient_id INTEGER NOT NULL REFERENCES users(id),
          slot_id INTEGER NOT NULL REFERENCES slots(id),
          status TEXT NOT NULL DEFAULT 'agendado', created TEXT NOT NULL,
          UNIQUE(patient_id, slot_id)
        );
        CREATE TABLE IF NOT EXISTS notifications (
          id INTEGER PRIMARY KEY, patient_id INTEGER NOT NULL REFERENCES users(id),
          booking_id INTEGER REFERENCES bookings(id), message TEXT NOT NULL,
          created TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_booking_slot ON bookings(slot_id, status);
        CREATE INDEX IF NOT EXISTS idx_notifications ON notifications(patient_id, created);
        ''')
        admin_email = os.getenv('ADMIN_EMAIL', '').lower().strip()
        admin_pw = os.getenv('ADMIN_PASSWORD', '')
        if admin_email and len(admin_pw) >= 12:
            if not c.execute('SELECT id FROM users WHERE email=?', (admin_email,)).fetchone():
                c.execute('INSERT INTO users(name,email,password,role,created) VALUES(?,?,?,?,?)',
                          ('Equipe UBAS', admin_email, pw_hash(admin_pw), 'staff', datetime.now().isoformat()))
        # Oferta demonstrativa criada apenas em banco novo, não substituir agendas reais.
        count = c.execute('SELECT COUNT(*) FROM slots').fetchone()[0]
        if not count:
            for n in range(1, 15):
                day = date.today() + timedelta(days=n)
                if day.weekday() < 5:
                    for service in SERVICES:
                        for hour in ['08:00', '09:00', '10:00', '14:00']:
                            c.execute('INSERT OR IGNORE INTO slots(service,day,hour,capacity) VALUES(?,?,?,?)',
                                      (service, day.isoformat(), hour, 4))


def public_user(row):
    return dict(id=row['id'], name=row['name'], email=row['email'], role=row['role'], cpf=row['cpf'],
                birth=row['birth'], sus=row['sus'], phone=row['phone'])


def notify(c, patient_id, booking_id, message):
    c.execute('INSERT INTO notifications(patient_id,booking_id,message,created) VALUES(?,?,?,?)',
              (patient_id, booking_id, message, datetime.now().isoformat(timespec='seconds')))


def cpf_valid(cpf):
    if len(cpf) != 11 or cpf == cpf[0]*11:
        return False
    for length in (9, 10):
        total = sum(int(ch) * (length+1-i) for i, ch in enumerate(cpf[:length]))
        digit = (total*10) % 11
        if digit == 10: digit = 0
        if digit != int(cpf[length]): return False
    return True


class App(BaseHTTPRequestHandler):
    server_version = 'VilaSaude/0.1'
    def log_message(self, fmt, *args):
        print('%s - %s' % (self.address_string(), fmt % args))
    def headers_common(self, mime='application/json; charset=utf-8'):
        self.send_header('Content-Type', mime)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'")
    def send_json(self, value, code=200, cookie=None):
        encoded = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(code)
        self.headers_common()
        if cookie: self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
    def error(self, message, code=400):
        self.send_json({'error': message}, code)
    def get_user(self):
        cookie = SimpleCookie()
        try: cookie.load(self.headers.get('Cookie',''))
        except Exception: return None
        token = cookie.get('vila_session')
        if not token: return None
        state = SESSIONS.get(token.value)
        if not state or state[1] < time.time():
            SESSIONS.pop(token.value, None)
            return None
        with db() as c:
            row = c.execute('SELECT * FROM users WHERE id=?', (state[0],)).fetchone()
        return row
    def require(self, role=None):
        user = self.get_user()
        if not user:
            self.error('Faça login para continuar.', 401)
            return None
        if role and user['role'] != role:
            self.error('Acesso restrito à equipe da unidade.', 403)
            return None
        return user
    def json_body(self):
        if int(self.headers.get('Content-Length','0')) > MAX_BODY: raise ValueError('Dados muito extensos.')
        try: data = json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        except Exception: raise ValueError('JSON inválido.')
        if not isinstance(data, dict): raise ValueError('Dados inválidos.')
        return data
    def do_GET(self):
        p = urlparse(self.path).path
        if not p.startswith('/api/'):
            files = {'/':'index.html', '/index.html':'index.html','/app.js':'app.js','/style.css':'style.css','/favicon.svg':'favicon.svg'}
            if p not in files: return self.error('Arquivo não encontrado.',404)
            f = ROOT/'static'/files[p]
            content = f.read_bytes()
            mime = ('text/html' if p in ('/','/index.html') else 'text/javascript' if p == '/app.js' else 'text/css' if p == '/style.css' else 'image/svg+xml')
            self.send_response(200); self.headers_common(mime+'; charset=utf-8'); self.send_header('Content-Length',str(len(content))); self.end_headers(); self.wfile.write(content)
            return
        if p == '/api/me':
            u = self.get_user(); return self.send_json({'user': public_user(u) if u else None})
        if p == '/api/slots':
            user = self.require()
            if not user: return
            with db() as c:
                slots = c.execute('''SELECT s.*, (SELECT COUNT(*) FROM bookings b WHERE b.slot_id=s.id AND b.status NOT IN ('cancelado', 'ausente')) AS used
                FROM slots s WHERE s.day>=? ORDER BY s.day,s.hour,s.service''',(date.today().isoformat(),)).fetchall()
                return self.send_json({'slots':[dict(x) for x in slots]})
        if p == '/api/bookings':
            user = self.require()
            if not user: return
            with db() as c:
                if user['role']=='staff':
                    rows = c.execute('''SELECT b.id,b.patient_id,b.status,b.created,s.service,s.day,s.hour,s.id AS slot_id,u.name AS patient_name
                       FROM bookings b JOIN slots s ON s.id=b.slot_id JOIN users u ON u.id=b.patient_id
                       WHERE s.day >= ? ORDER BY s.day,s.hour,b.created,b.id''', (date.today().isoformat(),)).fetchall()
                else:
                    rows = c.execute('''SELECT b.id,b.patient_id,b.status,b.created,s.service,s.day,s.hour,s.id AS slot_id
                       FROM bookings b JOIN slots s ON s.id=b.slot_id WHERE b.patient_id=? ORDER BY s.day DESC,s.hour DESC''',(user['id'],)).fetchall()
                all_rows = [dict(r) for r in rows]
                for x in all_rows:
                    peers = c.execute('''SELECT b.id,b.status FROM bookings b WHERE b.slot_id=? AND b.status IN ('agendado','em_atendimento') ORDER BY CASE WHEN b.status='em_atendimento' THEN 0 ELSE 1 END,b.created,b.id''',(x['slot_id'],)).fetchall()
                    x['position'] = next((i+1 for i,z in enumerate(peers) if z['id']==x['id']), None)
                    x['estimated_minutes'] = (x['position']-1)*15 if x['position'] else None
                return self.send_json({'bookings':all_rows})
        if p == '/api/notifications':
            user = self.require()
            if not user: return
            with db() as c:
                rows=c.execute('SELECT id,message,created,read FROM notifications WHERE patient_id=? ORDER BY id DESC LIMIT 40',(user['id'],)).fetchall()
                return self.send_json({'notifications':[dict(x) for x in rows]})
        if p == '/api/report':
            user=self.require('staff')
            if not user:return
            with db() as c:
                rows=c.execute('SELECT status, COUNT(*) AS amount FROM bookings GROUP BY status').fetchall()
                return self.send_json({'by_status':[dict(r) for r in rows]})
        return self.error('Rota inexistente.',404)
    def do_POST(self):
        p = urlparse(self.path).path
        # Same-origin check to reduce CSRF exposure on cookie-authenticated routes.
        origin = self.headers.get('Origin')
        if origin:
            host=self.headers.get('Host','')
            if urlparse(origin).netloc != host:
                return self.error('Origem não autorizada.',403)
        try: data = self.json_body()
        except ValueError as e: return self.error(str(e))
        if p in ('/api/register','/api/login'):
            key=(self.client_address[0],p)
            hits=[v for v in ATTEMPTS.get(key,[]) if time.time()-v<900]
            if len(hits)>=15: return self.error('Muitas tentativas. Aguarde 15 minutos.',429)
            hits.append(time.time()); ATTEMPTS[key]=hits
        if p == '/api/register':
            name=str(data.get('name','')).strip()[:100]
            email=str(data.get('email','')).strip().lower()[:120]
            cpf=re.sub(r'\D','',str(data.get('cpf','')))
            sus=re.sub(r'\D','',str(data.get('sus',''))) or None
            birth=str(data.get('birth',''))
            phone=re.sub(r'\D','',str(data.get('phone','')))[:15]
            password=str(data.get('password',''))
            if len(name)<3 or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email) or not cpf_valid(cpf):
                return self.error('Informe nome, e-mail e CPF válidos.')
            try:
                birthday=date.fromisoformat(birth)
                if birthday>=date.today() or birthday<date(1900,1,1):raise ValueError()
            except ValueError:return self.error('Data de nascimento inválida.')
            if len(password)<10: return self.error('Use uma senha com no mínimo 10 caracteres.')
            if sus and len(sus)!=15:return self.error('Cartão SUS deve ter 15 dígitos.')
            with db() as c:
                try:
                    cur=c.execute('INSERT INTO users(name,email,cpf,sus,birth,phone,password,role,created) VALUES(?,?,?,?,?,?,?,?,?)',
                    (name,email,cpf,sus,birth,phone,pw_hash(password),'patient',datetime.now().isoformat()))
                except sqlite3.IntegrityError:return self.error('CPF, cartão SUS ou e-mail já cadastrado.',409)
                return self.send_json({'ok':True},201)
        if p == '/api/login':
            email=str(data.get('email','')).strip().lower()
            password=str(data.get('password',''))
            with db() as c: row=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
            if not row or not pw_check(password,row['password']): return self.error('Credenciais inválidas.',401)
            token=secrets.token_urlsafe(32)
            SESSIONS[token]=(row['id'],time.time()+60*60*8)
            cookie=f'vila_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+('; Secure' if SECURE_COOKIES else '')
            return self.send_json({'user':public_user(row)},cookie=cookie)
        if p == '/api/logout':
            cookie=SimpleCookie(); cookie.load(self.headers.get('Cookie',''))
            if cookie.get('vila_session'): SESSIONS.pop(cookie['vila_session'].value,None)
            return self.send_json({'ok':True},cookie='vila_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
        if p == '/api/bookings':
            u=self.require('patient')
            if not u:return
            try: slot_id=int(data.get('slot_id',0))
            except (TypeError,ValueError): return self.error('Horário inválido.')
            try:
                with db() as c:
                    c.execute('BEGIN IMMEDIATE')
                    slot=c.execute('SELECT * FROM slots WHERE id=?',(slot_id,)).fetchone()
                    if not slot or slot['day']<date.today().isoformat():return self.error('Horário indisponível.')
                    count=c.execute("SELECT COUNT(*) FROM bookings WHERE slot_id=? AND status NOT IN ('cancelado','ausente')",(slot_id,)).fetchone()[0]
                    if count>=slot['capacity']:return self.error('Todas as vagas desse horário foram preenchidas.',409)
                    existent=c.execute("SELECT id FROM bookings WHERE patient_id=? AND slot_id=? AND status NOT IN ('cancelado','ausente')",(u['id'],slot_id)).fetchone()
                    if existent:return self.error('Você já tem esse agendamento.',409)
                    cur=c.execute('INSERT INTO bookings(patient_id,slot_id,status,created) VALUES(?,?,?,?)', (u['id'],slot_id,'agendado',datetime.now().isoformat(timespec='seconds')))
                    notify(c,u['id'],cur.lastrowid,f'Agendamento confirmado: {slot["service"]} em {slot["day"]} às {slot["hour"]}.')
                    return self.send_json({'ok':True,'id':cur.lastrowid},201)
            except sqlite3.IntegrityError:return self.error('Agendamento já existente.',409)
        if p == '/api/status':
            u=self.require('staff')
            if not u:return
            try: bid=int(data.get('id')); status=str(data.get('status'))
            except (ValueError,TypeError):return self.error('Dados inválidos.')
            if status not in ['em_atendimento','atendido','ausente','cancelado']:return self.error('Status não permitido.')
            with db() as c:
                booking=c.execute('SELECT * FROM bookings WHERE id=?',(bid,)).fetchone()
                if not booking:return self.error('Agendamento não encontrado.',404)
                if booking['status'] in ('atendido','ausente','cancelado'):return self.error('Esse atendimento já foi encerrado.',409)
                if status=='em_atendimento' and booking['status']!='agendado':return self.error('Transição inválida.',409)
                c.execute('UPDATE bookings SET status=? WHERE id=?',(status,bid))
                notify(c,booking['patient_id'],bid,'Seu atendimento foi atualizado para: '+status.replace('_',' ')+'.')
                if status in ('em_atendimento','atendido','ausente'):
                    s=c.execute('SELECT slot_id FROM bookings WHERE id=?',(bid,)).fetchone()
                    others=c.execute("SELECT id,patient_id FROM bookings WHERE slot_id=? AND status='agendado' ORDER BY created,id LIMIT 2",(s['slot_id'],)).fetchall()
                    for i,other in enumerate(others):
                        if i==0:notify(c,other['patient_id'],other['id'],'Sua vez está se aproximando. Acompanhe a fila no aplicativo.')
                return self.send_json({'ok':True})
        if p == '/api/notifications/read':
            u=self.require()
            if not u:return
            with db() as c:c.execute('UPDATE notifications SET read=1 WHERE patient_id=?',(u['id'],))
            return self.send_json({'ok':True})
        return self.error('Rota inexistente.',404)


if __name__=='__main__':
    init()
    print(f'Vila+Saúde no http://{HOST}:{PORT}')
    ThreadingHTTPServer((HOST,PORT),App).serve_forever()

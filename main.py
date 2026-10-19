import os, secrets, html
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine, String, Text, Integer, Float, Boolean, DateTime, ForeignKey, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from pwdlib import PasswordHash

APP_NAME = "Amir Nano Railway"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
password_hash = PasswordHash.recommended()

class Base(DeclarativeBase): pass

class Host(Base):
    __tablename__ = "hosts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    address: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    status: Mapped[str] = mapped_column(String(40), default="unknown")
    notes: Mapped[str] = mapped_column(Text, default="")

class Node(Base):
    __tablename__ = "nodes"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    host_id: Mapped[Optional[int]] = mapped_column(ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    address: Mapped[str] = mapped_column(String(255), default="")
    port: Mapped[int] = mapped_column(Integer, default=443)
    status: Mapped[str] = mapped_column(String(40), default="unknown")
    notes: Mapped[str] = mapped_column(Text, default="")
    host: Mapped[Optional[Host]] = relationship()

class Core(Base):
    __tablename__ = "cores"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[str] = mapped_column(String(80), default="")
    notes: Mapped[str] = mapped_column(Text, default="")

class Group(Base):
    __tablename__ = "groups"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")

class User(Base):
    __tablename__ = "panel_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True)
    group_id: Mapped[Optional[int]] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), nullable=True)
    usage_gb: Mapped[float] = mapped_column(Float, default=0)
    limit_gb: Mapped[float] = mapped_column(Float, default=0)
    expires_at: Mapped[str] = mapped_column(String(40), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    subscription_token: Mapped[str] = mapped_column(String(80), unique=True, default=lambda: secrets.token_urlsafe(32))
    group: Mapped[Optional[Group]] = relationship()

class Config(Base):
    __tablename__ = "configs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    protocol: Mapped[str] = mapped_column(String(20))
    config_text: Mapped[str] = mapped_column(Text)
    group_id: Mapped[Optional[int]] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    group: Mapped[Optional[Group]] = relationship()

Base.metadata.create_all(engine)
app = FastAPI(title=APP_NAME)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "CHANGE_ME_BEFORE_DEPLOYING_TO_A_LONG_RANDOM_SECRET"), https_only=os.getenv("COOKIE_HTTPS_ONLY", "true").lower() == "true", same_site="lax", max_age=60 * 60 * 8)

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

NAV = [("dashboard", "داشبورد"), ("hosts", "Hosts"), ("nodes", "Nodes"), ("cores", "Cores"), ("groups", "Groups"), ("users", "Users"), ("configs", "Configs")]
SCHEMAS = {
 "hosts": (Host, "هاست‌ها", [("name","نام", "text"),("address","آدرس / IP","text"),("port","پورت","number"),("status","وضعیت","text"),("notes","توضیحات","textarea")]),
 "nodes": (Node, "نودها", [("name","نام","text"),("host_id","شناسه Host (اختیاری)","number"),("address","آدرس / IP","text"),("port","پورت","number"),("status","وضعیت","text"),("notes","توضیحات","textarea")]),
 "cores": (Core, "Cores", [("name","نام Core","text"),("version","نسخه","text"),("notes","توضیحات","textarea")]),
 "groups": (Group, "Groups", [("name","نام گروه","text"),("description","توضیحات","textarea")]),
 "users": (User, "Users", [("username","نام کاربر","text"),("group_id","شناسه Group (اختیاری)","number"),("usage_gb","Usage (GB) دستی","number"),("limit_gb","سقف حجم (GB)","number"),("expires_at","تاریخ انقضا (متن)","text"),("active","فعال؟ (true/false)","text")]),
 "configs": (Config, "Configs", [("name","نام کانفیگ","text"),("protocol","پروتکل: VLESS / VMess / Trojan","text"),("config_text","متن کامل کانفیگ","textarea"),("group_id","شناسه Group (اختیاری)","number"),("enabled","فعال؟ (true/false)","text"),("notes","توضیحات","textarea")]),
}

def esc(x): return html.escape("" if x is None else str(x))
def is_logged(request): return bool(request.session.get("admin"))
def csrf_token(request):
    if not request.session.get("csrf"): request.session["csrf"] = secrets.token_urlsafe(24)
    return request.session["csrf"]
def check_csrf(request, token):
    if not token or not secrets.compare_digest(str(request.session.get("csrf", "")), str(token)):
        raise HTTPException(403, "Invalid CSRF token")
def page(request, title, body):
    token = csrf_token(request)
    nav = "".join(f'<a class="navitem {"active" if key==title else ""}" href="/{key}">{label}</a>' for key,label in NAV)
    return HTMLResponse(f'''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(title)} · {APP_NAME}</title><style>
:root{{--bg:#070b14;--surface:#0d1422;--card:#111d30;--line:#243650;--text:#f1f6ff;--muted:#9aacc6;--accent:#41d6c3;--accent2:#3b82f6}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(ellipse at 80% 0%,#13284a 0%,transparent 35%),var(--bg);color:var(--text);font-family:Tahoma,Arial,sans-serif}}a{{color:#8fe9df;text-decoration:none}}.layout{{display:flex;min-height:100vh}}aside{{width:252px;padding:22px 15px;background:rgba(8,14,25,.96);border-left:1px solid var(--line);flex-shrink:0;display:flex;flex-direction:column}}.brand{{font-weight:900;font-size:19px;line-height:1.7;margin:3px 10px 24px;color:white}}.brand span{{color:var(--accent)}}.brand small{{display:block;color:var(--muted);font-size:10px;font-weight:normal;letter-spacing:1.8px}}nav{{display:grid;gap:6px}}.navitem{{display:flex;align-items:center;gap:10px;padding:12px 13px;border:1px solid transparent;border-radius:12px;color:var(--muted);transition:.18s}}.navitem:before{{content:"";width:6px;height:6px;border-radius:50%;background:#536781;flex-shrink:0}}.navitem:hover,.navitem.active{{background:linear-gradient(110deg,rgba(65,214,195,.13),rgba(59,130,246,.08));border-color:#254b5b;color:#fff}}.navitem.active:before{{background:var(--accent);box-shadow:0 0 12px var(--accent)}}aside>form{{margin-top:auto!important;padding-top:22px}}main{{padding:30px clamp(16px,3vw,42px);width:100%;min-width:0;max-width:1600px;margin:0 auto}}h1{{margin:0 0 8px;font-size:clamp(22px,3vw,30px)}}h2,h3{{margin-top:0}}.sub{{color:var(--muted);margin-bottom:25px;line-height:1.9;font-size:13px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin:22px 0}}.stat,.panel{{background:linear-gradient(145deg,rgba(17,29,48,.96),rgba(11,19,33,.96));border:1px solid var(--line);border-radius:18px;padding:19px;box-shadow:0 12px 32px rgba(0,0,0,.12)}}.stat{{position:relative;overflow:hidden;min-height:112px}}.stat:after{{content:"";position:absolute;inset:auto -15px -32px auto;width:95px;height:95px;border-radius:50%;background:rgba(65,214,195,.06)}}.stat small{{color:var(--muted);font-size:12px}}.num{{font-size:30px;font-weight:800;margin-top:13px;color:#fff}}.panel{{margin:17px 0}}.toolbar{{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}}.toolbar .sub{{margin-bottom:0}}input,textarea,select{{width:100%;background:#080f1c;color:var(--text);border:1px solid #2a3d59;border-radius:10px;padding:12px 13px;font:inherit;outline:none;transition:border-color .18s,box-shadow .18s}}input:focus,textarea:focus,select:focus{{border-color:var(--accent);box-shadow:0 0 0 3px rgba(65,214,195,.09)}}textarea{{min-height:110px;resize:vertical}}label{{display:block;color:#c3d1e5;font-size:12px;margin-bottom:8px}}.field{{margin:10px 0 15px}}button,.btn{{display:inline-flex;align-items:center;justify-content:center;gap:7px;border:1px solid transparent;border-radius:10px;background:linear-gradient(110deg,var(--accent2),#2563eb);color:white;padding:11px 16px;font:inherit;font-size:13px;font-weight:bold;cursor:pointer;transition:transform .15s,filter .15s}}button:hover,.btn:hover{{filter:brightness(1.1);transform:translateY(-1px)}}.danger{{background:#7f263c;border-color:#a33b55}}.secondary{{background:#192a42;border-color:#2d4564;color:#d8e6f9}}table{{width:100%;border-collapse:collapse;min-width:650px}}th,td{{padding:14px 12px;text-align:right;border-bottom:1px solid rgba(36,54,80,.8);vertical-align:top;max-width:320px;overflow-wrap:anywhere;font-size:13px}}th{{color:#9eb2ce;font-weight:normal;background:rgba(7,12,21,.5)}}tbody tr:hover{{background:rgba(65,214,195,.035)}}.tablewrap{{overflow:auto;padding:0}}.tablewrap table{{margin:0}}.formgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:4px 18px}}.pill{{display:inline-block;background:#123c39;color:#91f3e2;padding:5px 9px;border-radius:30px;font-size:11px}}.notice{{padding:14px 16px;border:1px solid #69562a;background:rgba(68,51,13,.35);border-radius:12px;color:#f5d98a;line-height:1.9}}.login{{max-width:430px;margin:8vh auto;padding:28px}}.muted{{color:var(--muted);font-size:12px;line-height:1.8}}.actions{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}}.actions form{{margin:0}}.empty{{padding:28px!important;text-align:center;color:var(--muted)}}@media(max-width:760px){{.layout{{display:block}}aside{{width:100%;border-left:0;border-bottom:1px solid var(--line);padding:12px 12px 10px}}.brand{{margin:3px 8px 10px;font-size:17px}}.brand small{{display:inline;margin-right:8px}}nav{{display:flex;overflow:auto;gap:5px;padding-bottom:3px}}.navitem{{white-space:nowrap;padding:10px 12px;font-size:12px}}.navitem:before{{display:none}}aside>form{{margin:8px 0 0!important;padding:0!important}}aside>form button{{width:auto!important;padding:8px 12px}}main{{padding:19px 13px}}h1{{font-size:22px}}.grid{{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}.stat{{padding:14px;min-height:98px}}.num{{font-size:25px}}.panel{{padding:14px;border-radius:14px}}.formgrid{{grid-template-columns:1fr}}.toolbar .btn{{width:100%}}}}
</style></head><body><div class="layout"><aside><div class="brand">AMIR NANO <span>RAILWAY</span><small>CONTROL CENTER</small></div><nav>{nav}</nav><form method="post" action="/logout" style="margin:16px 4px"><input type="hidden" name="csrf" value="{token}"><button class="secondary" style="width:100%">خروج مدیر</button></form></aside><main>{body}</main></div></body></html>''')

def require_admin(request):
    if not is_logged(request): raise HTTPException(401, "Login required")

@app.get("/health")
def health(): return {"status":"ok"}

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if is_logged(request): return RedirectResponse("/dashboard", 303)
    t=csrf_token(request)
    return HTMLResponse(f'''<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ورود مدیر</title><style>body{{background:#080d18;color:#eef4ff;font-family:Tahoma;display:grid;place-items:center;min-height:100vh;margin:0}}.box{{width:min(92%,420px);background:#101a2b;border:1px solid #24334b;border-radius:18px;padding:28px}}input{{display:block;width:100%;box-sizing:border-box;margin:8px 0 16px;padding:12px;background:#091220;color:white;border:1px solid #2c3e5a;border-radius:8px}}button{{width:100%;padding:12px;background:#4285ff;color:white;border:0;border-radius:8px;font-size:16px}}small{{color:#9eb0ca}}</style><div class="box"><h2>AMIR NANO RAILWAY</h2><p>ورود مدیر اصلی</p><form method="post" action="/login"><input type="hidden" name="csrf" value="{t}"><label>نام کاربری</label><input name="username" autocomplete="username" required><label>رمز عبور</label><input name="password" type="password" autocomplete="current-password" required><button>ورود</button></form><small>دسترسی فقط برای مدیر اصلی</small></div></html>''')

@app.post("/login")
def login(request: Request, username: str=Form(...), password: str=Form(...), csrf: str=Form(...)):
    check_csrf(request, csrf)
    if not ADMIN_PASSWORD or ADMIN_PASSWORD == "change-this-password" or not secrets.compare_digest(username, ADMIN_USERNAME) or not secrets.compare_digest(password, ADMIN_PASSWORD):
        return HTMLResponse("ورود ناموفق است. متغیرهای ADMIN_USERNAME و ADMIN_PASSWORD را در Railway بررسی کن.", status_code=401)
    request.session.clear(); request.session["admin"] = True; request.session["csrf"] = secrets.token_urlsafe(24)
    return RedirectResponse("/dashboard", 303)

@app.post("/logout")
def logout(request: Request, csrf: str=Form(...)):
    require_admin(request); check_csrf(request, csrf); request.session.clear(); return RedirectResponse("/login", 303)

@app.get("/")
def root(): return RedirectResponse("/dashboard", 303)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    require_admin(request)
    with SessionLocal() as db:
        counts={"Hosts":db.scalar(select(func.count()).select_from(Host)),"Nodes":db.scalar(select(func.count()).select_from(Node)),"Cores":db.scalar(select(func.count()).select_from(Core)),"Groups":db.scalar(select(func.count()).select_from(Group)),"Users":db.scalar(select(func.count()).select_from(User)),"Configs":db.scalar(select(func.count()).select_from(Config))}
        usage=db.scalar(select(func.coalesce(func.sum(User.usage_gb),0))) or 0
    cards="".join(f'<div class="stat"><small>{k}</small><div class="num">{v}</div></div>' for k,v in counts.items())
    body=f'<h1>داشبورد مدیریت</h1><div class="sub">خوش آمدی؛ اطلاعات را از منوی کناری مدیریت کن.</div><div class="grid">{cards}<div class="stat"><small>مجموع Usage دستی (GB)</small><div class="num">{usage:g}</div></div></div><div class="panel"><h3>شروع سریع</h3><p>۱. ابتدا Groups بساز. ۲. Users ایجاد کن و شناسه Group را وارد کن. ۳. کانفیگ‌ها را به همان Group وصل کن. ۴. لینک ساب کاربر را از بخش Users کپی کن.</p><div class="notice">Usage در این نسخه دستی است. لینک ساب یک آدرس خصوصی برای توزیع کانفیگ‌هایی است که خودت وارد کرده‌ای.</div><p class="muted">ترتیب پیشنهادی: Host ← Node ← Core ← Group ← User ← Config. برای اتصال Node به Host و User/Config به Group از فهرست انتخابی استفاده کن.</p></div>'
    return page(request,"dashboard",body)

@app.get("/{section}", response_class=HTMLResponse)
def list_section(section: str, request: Request):
    require_admin(request)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    model, label, fields=SCHEMAS[section]
    with SessionLocal() as db: rows=db.scalars(select(model).order_by(model.id.desc()).limit(300)).all(); rows=[{c.name:getattr(r,c.name) for c in model.__table__.columns} for r in rows]
    heads=''.join(f'<th>{esc(f[1])}</th>' for f in fields[:5])
    bodyrows=''
    for row in rows:
        vals=''.join(f'<td>{esc(str(row.get(f[0],""))[:180])}</td>' for f in fields[:5])
        extra=''
        if section=='users':
            suburl=f"{str(request.base_url).rstrip('/')}/sub/{row['subscription_token']}"
            extra=f'<td><a href="{esc(suburl)}" target="_blank">بازکردن ساب</a><br><button type="button" class="secondary" onclick="navigator.clipboard.writeText(\'{esc(suburl)}\')">کپی لینک</button></td>'
        token=csrf_token(request)
        edit=f'<a class="btn secondary" href="/{section}/{row["id"]}/edit">ویرایش</a>'
        delete=f'<form method="post" action="/{section}/{row["id"]}/delete" onsubmit="return confirm(\'حذف شود؟\')"><input type="hidden" name="csrf" value="{token}"><button class="danger">حذف</button></form>'
        bodyrows+=f'<tr><td>{row["id"]}</td>{vals}{extra}<td><div class="actions">{edit}{delete}</div></td></tr>'
    extrahead='<th>Subscription</th>' if section=='users' else ''
    body=f'<div class="toolbar"><div><h1>{label}</h1><div class="sub">ثبت و مدیریت اطلاعات — حداکثر ۳۰۰ رکورد اخیر نمایش داده می‌شود.</div></div><a class="btn" href="/{section}/new">+ افزودن مورد</a></div><div class="panel tablewrap"><table><thead><tr><th>ID</th>{heads}{extrahead}<th>عملیات</th></tr></thead><tbody>{bodyrows or "<tr><td colspan=10>هنوز موردی ثبت نشده است.</td></tr>"}</tbody></table></div>'
    return page(request,section,body)

def field_value(obj, key):
    val=getattr(obj,key,None)
    if key in ("enabled","active"): return "true" if val else "false"
    return "" if val is None else str(val)

def render_form(request, section, obj=None, error=""):
    model,label,fields=SCHEMAS[section]; token=csrf_token(request); is_edit=obj is not None
    inputs=''
    relation_options = {}
    with SessionLocal() as db:
        relation_options["host_id"] = [(x.id, x.name) for x in db.scalars(select(Host).order_by(Host.name)).all()]
        relation_options["group_id"] = [(x.id, x.name) for x in db.scalars(select(Group).order_by(Group.name)).all()]
    for key, title, kind in fields:
        val=field_value(obj,key) if is_edit else ("true" if key in ("active","enabled") else "443" if key=="port" else "0" if key in ("usage_gb","limit_gb") else "")
        if key=="config_text": val=field_value(obj,key) if is_edit else ""
        if key in ("host_id","group_id"):
            options='<option value="">بدون اتصال</option>'
            for opt_id,opt_name in relation_options.get(key,[]):
                selected=' selected' if str(val)==str(opt_id) else ''
                options+=f'<option value="{opt_id}"{selected}>{esc(opt_name)} · ID {opt_id}</option>'
            inp=f'<select name="{key}">{options}</select>'
        elif key in ("active","enabled"):
            chosen=str(val).lower()
            inp='<select name="'+key+'"><option value="true"'+(' selected' if chosen in ("true","1","yes","on") else '')+'>فعال</option><option value="false"'+(' selected' if chosen not in ("true","1","yes","on") else '')+'>غیرفعال</option></select>'
        elif key=="protocol":
            chosen=str(val).upper()
            inp='<select name="protocol"><option value="">انتخاب پروتکل</option>'+''.join(f'<option value="{p}"{(" selected" if chosen==p else "")}>{p}</option>' for p in ("VLESS","VMESS","TROJAN"))+'</select>'
        elif key=="status":
            chosen=str(val).lower()
            statuses=[("unknown","نامشخص"),("online","آنلاین"),("offline","آفلاین"),("maintenance","در حال تعمیر")]
            inp='<select name="status">'+''.join(f'<option value="{v}"{(" selected" if chosen==v else "")}>{label}</option>' for v,label in statuses)+'</select>'
        elif kind=="textarea":
            inp=f'<textarea name="{key}">{esc(val)}</textarea>'
        else:
            inp=f'<input name="{key}" type="{"number" if kind=="number" else "text"}" value="{esc(val)}" {"step=any" if key in ("usage_gb","limit_gb") else ""}>'
        inputs+=f'<div class="field"><label>{esc(title)}</label>{inp}</div>'
    rid=obj.id if is_edit else "new"
    body=f'<h1>{"ویرایش" if is_edit else "افزودن"} — {label}</h1><div class="sub">فیلدهای متنی را با دقت وارد کن.</div>{f"<div class=notice>{esc(error)}</div>" if error else ""}<div class="panel"><form method="post" action="/{section}/{rid}"><input type="hidden" name="csrf" value="{token}"><div class="formgrid">{inputs}</div><div class="actions"><button>ذخیره</button><a class="btn secondary" href="/{section}">بازگشت</a></div></form></div>'
    return page(request,section,body)

@app.get("/{section}/new", response_class=HTMLResponse)
def new_form(section: str, request: Request):
    require_admin(request)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    return render_form(request,section)

@app.get("/{section}/{item_id}/edit", response_class=HTMLResponse)
def edit_form(section: str, item_id: int, request: Request):
    require_admin(request)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    model=SCHEMAS[section][0]
    with SessionLocal() as db: obj=db.get(model,item_id)
    if not obj: raise HTTPException(404,"Item not found")
    return render_form(request,section,obj)

@app.post("/{section}/new")
@app.post("/{section}/{item_id:int}")
def save_item(request: Request, section: str, item_id: Optional[int]=None, csrf: str=Form(...), name: Optional[str]=Form(None), address: Optional[str]=Form(None), port: Optional[int]=Form(None), status: Optional[str]=Form(None), notes: Optional[str]=Form(None), host_id: Optional[str]=Form(None), version: Optional[str]=Form(None), description: Optional[str]=Form(None), username: Optional[str]=Form(None), group_id: Optional[str]=Form(None), usage_gb: Optional[float]=Form(None), limit_gb: Optional[float]=Form(None), expires_at: Optional[str]=Form(None), active: Optional[str]=Form(None), protocol: Optional[str]=Form(None), config_text: Optional[str]=Form(None), enabled: Optional[str]=Form(None)):
    require_admin(request); check_csrf(request,csrf)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    model,label,fields=SCHEMAS[section]
    raw=locals()
    allowed={f[0] for f in fields}
    data={k:raw[k] for k in allowed if k in raw}
    for k in ("host_id", "group_id"):
        if k in data:
            data[k] = int(data[k]) if data[k] not in (None, "") else None
    for k in ("active","enabled"):
        if k in data: data[k]=str(data[k]).lower() in ("true","1","yes","on")
    for k in ("usage_gb","limit_gb"):
        if k in data and data[k] is None: data[k]=0
    if section in ("hosts","nodes","cores","groups","users","configs"):
        required={"hosts":["name"],"nodes":["name"],"cores":["name"],"groups":["name"],"users":["username"],"configs":["name","protocol","config_text"]}[section]
        if any(not data.get(k) for k in required):
            with SessionLocal() as db: obj=db.get(model,item_id) if item_id else None
            return render_form(request,section,obj,"فیلدهای ضروری را تکمیل کن.")
    if section=="configs" and data.get("protocol"," ").upper() not in ("VLESS","VMESS","TROJAN"):
        with SessionLocal() as db: obj=db.get(model,item_id) if item_id else None
        return render_form(request,section,obj,"پروتکل باید VLESS، VMess یا Trojan باشد.")
    with SessionLocal() as db:
        if item_id:
            obj=db.get(model,item_id)
            if not obj: raise HTTPException(404,"Item not found")
        else: obj=model()
        for k,v in data.items():
            if hasattr(obj,k): setattr(obj,k,v)
        db.add(obj); db.commit()
    return RedirectResponse(f"/{section}",303)

@app.post("/{section}/{item_id}/delete")
def delete_item(section: str, item_id: int, request: Request, csrf: str=Form(...)):
    require_admin(request); check_csrf(request,csrf)
    if section not in SCHEMAS: raise HTTPException(404,"Not found")
    model=SCHEMAS[section][0]
    with SessionLocal() as db:
        obj=db.get(model,item_id)
        if obj: db.delete(obj); db.commit()
    return RedirectResponse(f"/{section}",303)

@app.get("/sub/{token}")
def subscription(token: str):
    with SessionLocal() as db:
        user=db.scalar(select(User).where(User.subscription_token==token, User.active==True))
        if not user: raise HTTPException(404,"Subscription not found or disabled")
        query=select(Config).where(Config.enabled==True)
        if user.group_id is not None: query=query.where(Config.group_id==user.group_id)
        else: query=query.where(Config.group_id.is_(None))
        configs=db.scalars(query.order_by(Config.id)).all()
        text_out="\n".join(c.config_text.strip() for c in configs if c.config_text.strip())
    return PlainTextResponse(text_out or "# No active configurations assigned", media_type="text/plain; charset=utf-8")

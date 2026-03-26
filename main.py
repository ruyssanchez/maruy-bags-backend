from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import os, uuid, hashlib, hmac, base64, json
from datetime import datetime, timedelta
import httpx
import bcrypt

app = FastAPI(title="Maruy Bags API", version="6.2.0")

# ── CORS ──────────────────────────────────────────────────────────────────────
ALLOWED_ORIGINS = [
    o.strip() for o in
    os.getenv("ALLOWED_ORIGINS", "http://localhost,http://127.0.0.1").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

os.makedirs("static/uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="static/uploads"), name="uploads")

# ── SUPABASE ──────────────────────────────────────────────────────────────────
SUPABASE_URL    = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY    = os.getenv("SUPABASE_KEY", "")
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "imagenes-productos")
SB = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}
def sb(t): return f"{SUPABASE_URL}/rest/v1/{t}"

# ── SUPABASE STORAGE ──────────────────────────────────────────────────────────
async def subir_a_supabase_storage(archivo: UploadFile) -> str:
    ext = os.path.splitext(archivo.filename)[1].lower()
    nombre = f"{uuid.uuid4().hex}{ext}"
    contenido = await archivo.read()
    upload_url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{nombre}"
    headers_storage = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": archivo.content_type or "image/jpeg",
    }
    async with httpx.AsyncClient() as c:
        res = await c.post(upload_url, headers=headers_storage, content=contenido)
    if res.status_code not in [200, 201]:
        raise HTTPException(500, f"Error subiendo imagen: {res.text}")
    return f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{nombre}"

# ── JWT ───────────────────────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET no configurado. Agrega esta variable en Render.")
JWT_HOURS = 24

def b64e(d): return base64.urlsafe_b64encode(d).rstrip(b'=').decode()
def b64d(s):
    s += '=' * (4 - len(s) % 4) if len(s) % 4 else ''
    return base64.urlsafe_b64decode(s)

def crear_jwt(username, rol):
    h = b64e(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    exp = int((datetime.utcnow() + timedelta(hours=JWT_HOURS)).timestamp())
    p = b64e(json.dumps({"sub":username,"rol":rol,"exp":exp}).encode())
    sig = b64e(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"

def verificar_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) != 3: raise ValueError("Token inválido")
        h, p, sig = parts
        sig_c = b64e(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, sig_c): raise ValueError("Firma inválida")
        data = json.loads(b64d(p))
        if data.get("exp",0) < int(datetime.utcnow().timestamp()): raise ValueError("Token expirado")
        return data
    except HTTPException: raise
    except Exception as e: raise HTTPException(401, str(e))

security = HTTPBearer()
def get_user(c: HTTPAuthorizationCredentials = Depends(security)): return verificar_jwt(c.credentials)
def require_admin(u: dict = Depends(get_user)):
    if u.get("rol") != "admin": raise HTTPException(403, "Solo administradores")
    return u

# ── MODELOS ───────────────────────────────────────────────────────────────────
class LoginReq(BaseModel):
    username: str
    password: str

class Producto(BaseModel):
    nombre: str
    categoria: str
    precio: float
    color: str
    badge: Optional[str] = None
    descripcion: str
    imagenes: Optional[List[str]] = []
    stock: int = 0

class ProductoUpdate(BaseModel):
    nombre: Optional[str] = None
    categoria: Optional[str] = None
    precio: Optional[float] = None
    color: Optional[str] = None
    badge: Optional[str] = None
    descripcion: Optional[str] = None
    imagenes: Optional[List[str]] = None
    stock: Optional[int] = None

class Pedido(BaseModel):
    cliente_nombre: str
    cliente_telefono: str
    cliente_ciudad: Optional[str] = ""
    productos: List[dict]
    total: float
    notas: Optional[str] = ""

class UsuarioCreate(BaseModel):
    username: str
    password: str
    rol: str

class UsuarioUpdate(BaseModel):
    password: Optional[str] = None
    rol: Optional[str] = None
    activo: Optional[bool] = None

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(req: LoginReq):
    url = sb("usuarios") + f"?username=eq.{req.username.lower()}&activo=eq.true&select=*"
    async with httpx.AsyncClient() as c:
        res = await c.get(url, headers=SB)
    data = res.json()
    if not data:
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    u = data[0]
    stored = u["password_hash"]
    # Soporta bcrypt (nuevo) y SHA-256 legacy (migración automática)
    if stored.startswith("$2b$") or stored.startswith("$2a$"):
        ok = bcrypt.checkpw(req.password.encode(), stored.encode())
    else:
        ok = hmac.compare_digest(stored, hashlib.sha256(req.password.encode()).hexdigest())
    if not ok:
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    return {"access_token": crear_jwt(u["username"], u["rol"]),
            "token_type": "bearer", "username": u["username"],
            "rol": u["rol"], "expires_in": JWT_HOURS * 3600}

@app.get("/api/auth/me")
def me(u: dict = Depends(get_user)):
    return {"username": u.get("sub"), "rol": u.get("rol")}

# ── USUARIOS ──────────────────────────────────────────────────────────────────
@app.get("/api/usuarios")
async def listar_usuarios(u: dict = Depends(require_admin)):
    async with httpx.AsyncClient() as c:
        res = await c.get(sb("usuarios")+"?select=id,username,rol,activo,creado_en&order=id.asc", headers=SB)
    return res.json()

@app.post("/api/usuarios", status_code=201)
async def crear_usuario(nuevo: UsuarioCreate, u: dict = Depends(require_admin)):
    if nuevo.rol not in ["admin","empleado"]: raise HTTPException(400,"Rol inválido")
    pwd_hash = bcrypt.hashpw(nuevo.password.encode(), bcrypt.gensalt()).decode()
    body = {"username": nuevo.username.lower(), "password_hash": pwd_hash, "rol": nuevo.rol, "activo": True}
    async with httpx.AsyncClient() as c:
        res = await c.post(sb("usuarios"), headers=SB, json=body)
    if res.status_code not in [200,201]: raise HTTPException(400,"Error creando usuario (¿ya existe?)")
    return res.json()[0]

@app.patch("/api/usuarios/{id}")
async def actualizar_usuario(id: int, cambios: UsuarioUpdate, u: dict = Depends(require_admin)):
    body = {}
    if cambios.password: body["password_hash"] = bcrypt.hashpw(cambios.password.encode(), bcrypt.gensalt()).decode()
    if cambios.rol:      body["rol"] = cambios.rol
    if cambios.activo is not None: body["activo"] = cambios.activo
    if not body: raise HTTPException(400,"Sin cambios")
    async with httpx.AsyncClient() as c:
        await c.patch(sb("usuarios")+f"?id=eq.{id}", headers=SB, json=body)
    return {"mensaje": "Usuario actualizado"}

@app.delete("/api/usuarios/{id}")
async def eliminar_usuario(id: int, u: dict = Depends(require_admin)):
    async with httpx.AsyncClient() as c:
        res = await c.get(sb("usuarios")+f"?id=eq.{id}&select=username", headers=SB)
    data = res.json()
    if data and data[0]["username"] == u.get("sub"):
        raise HTTPException(400, "No puedes eliminar tu propio usuario")
    async with httpx.AsyncClient() as c:
        res = await c.delete(sb("usuarios")+f"?id=eq.{id}", headers=SB)
    if res.status_code not in [200,204]: raise HTTPException(500,"Error eliminando usuario")
    return {"mensaje": f"Usuario {id} eliminado"}

# ── PRODUCTOS ─────────────────────────────────────────────────────────────────
def normalizar_imagenes(p):
    if not p.get("imagenes") or not isinstance(p["imagenes"], list):
        img = p.get("imagen","")
        p["imagenes"] = [img] if img else []
    else:
        p["imagenes"] = [i for i in p["imagenes"] if i]
    return p

@app.get("/api/productos")
async def listar_productos(categoria: Optional[str]=None, color: Optional[str]=None):
    url = sb("productos") + "?select=*&order=id.asc"
    if categoria: url += f"&categoria=eq.{categoria}"
    if color:     url += f"&color=eq.{color}"
    async with httpx.AsyncClient() as c:
        res = await c.get(url, headers=SB)
    if res.status_code != 200: raise HTTPException(500,"Error obteniendo productos")
    return [normalizar_imagenes(p) for p in res.json()]

@app.get("/api/productos/{id}")
async def obtener_producto(id: int):
    async with httpx.AsyncClient() as c:
        res = await c.get(sb("productos")+f"?id=eq.{id}&select=*", headers=SB)
    data = res.json()
    if not data: raise HTTPException(404,"Producto no encontrado")
    return normalizar_imagenes(data[0])

@app.post("/api/productos", status_code=201)
async def crear_producto(p: Producto, u: dict = Depends(require_admin)):
    body = p.dict()
    body["imagenes"] = p.imagenes or []
    async with httpx.AsyncClient() as c:
        res = await c.post(sb("productos"), headers=SB, json=body)
    if res.status_code not in [200,201]: raise HTTPException(500,"Error creando producto")
    return normalizar_imagenes(res.json()[0])

@app.patch("/api/productos/{id}")
async def actualizar_producto(id: int, cambios: ProductoUpdate, u: dict = Depends(get_user)):
    data = {k: v for k, v in cambios.dict().items() if v is not None}
    if not data: raise HTTPException(400,"Sin cambios")
    async with httpx.AsyncClient() as c:
        res = await c.patch(sb("productos")+f"?id=eq.{id}", headers=SB, json=data)
    if res.status_code not in [200,204]: raise HTTPException(500,"Error actualizando")
    return await obtener_producto(id)

@app.delete("/api/productos/{id}")
async def eliminar_producto(id: int, u: dict = Depends(require_admin)):
    async with httpx.AsyncClient() as c:
        res = await c.delete(sb("productos")+f"?id=eq.{id}", headers=SB)
    if res.status_code not in [200,204]: raise HTTPException(500,"Error eliminando")
    return {"mensaje": f"Producto {id} eliminado", "por": u.get("sub")}

@app.post("/api/productos/{id}/imagen")
async def subir_imagen(id: int, archivo: UploadFile = File(...), u: dict = Depends(get_user)):
    ext = os.path.splitext(archivo.filename)[1].lower()
    if ext not in [".jpg",".jpeg",".png",".webp"]: raise HTTPException(400,"Solo JPG, PNG, WEBP")
    url_img = await subir_a_supabase_storage(archivo)
    prod = await obtener_producto(id)
    imagenes = prod.get("imagenes", [])
    imagenes.append(url_img)
    await actualizar_producto(id, ProductoUpdate(imagenes=imagenes), u)
    return {"imagen_url": url_img, "imagenes": imagenes}

@app.delete("/api/productos/{id}/imagen/{idx}")
async def eliminar_imagen(id: int, idx: int, u: dict = Depends(get_user)):
    prod = await obtener_producto(id)
    imagenes = prod.get("imagenes", [])
    if idx >= len(imagenes): raise HTTPException(404,"Imagen no encontrada")
    imagenes.pop(idx)
    await actualizar_producto(id, ProductoUpdate(imagenes=imagenes), u)
    return {"imagenes": imagenes}

# ── PEDIDOS ───────────────────────────────────────────────────────────────────
@app.get("/api/pedidos")
async def listar_pedidos(estado: Optional[str]=None, u: dict = Depends(get_user)):
    url = sb("pedidos") + "?select=*&order=fecha.desc"
    if estado: url += f"&estado=eq.{estado}"
    async with httpx.AsyncClient() as c:
        res = await c.get(url, headers=SB)
    return res.json()

@app.post("/api/pedidos", status_code=201)
async def crear_pedido(pedido: Pedido):
    nuevo = {"fecha": datetime.now().isoformat(), "estado":"pendiente", **pedido.dict()}
    async with httpx.AsyncClient() as c:
        res = await c.post(sb("pedidos"), headers=SB, json=nuevo)
    if res.status_code not in [200,201]: raise HTTPException(500,"Error creando pedido")
    return res.json()[0] if res.json() else nuevo

@app.patch("/api/pedidos/{id}/estado")
async def cambiar_estado(id: int, estado: str, u: dict = Depends(get_user)):
    validos = ["pendiente","confirmado","enviado","entregado","cancelado"]
    if estado not in validos: raise HTTPException(400,f"Estados válidos: {validos}")
    async with httpx.AsyncClient() as c:
        await c.patch(sb("pedidos")+f"?id=eq.{id}", headers=SB, json={"estado":estado})
    return {"mensaje":f"Pedido {id} → {estado}"}

@app.delete("/api/pedidos/{id}")
async def eliminar_pedido(id: int, u: dict = Depends(require_admin)):
    async with httpx.AsyncClient() as c:
        res = await c.delete(sb("pedidos")+f"?id=eq.{id}", headers=SB)
    if res.status_code not in [200,204]: raise HTTPException(500,"Error eliminando pedido")
    return {"mensaje":f"Pedido {id} eliminado","por":u.get("sub")}

# ── STATS ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def estadisticas(u: dict = Depends(get_user)):
    async with httpx.AsyncClient() as c:
        p = await c.get(sb("productos")+"?select=id,categoria", headers=SB)
        o = await c.get(sb("pedidos")+"?select=id,estado,total", headers=SB)
    prods=p.json(); peds=o.json()
    return {
        "total_productos": len(prods),
        "total_pedidos": len(peds),
        "pedidos_pendientes": len([x for x in peds if x.get("estado")=="pendiente"]),
        "total_ventas": sum(float(x.get("total",0)) for x in peds if x.get("estado")!="cancelado"),
        "categorias": list(set(x["categoria"] for x in prods)),
    }

@app.get("/")
def root(): return {"mensaje":"Maruy Bags API v6.2","docs":"/docs"}

from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import os, uuid, shutil, hashlib, hmac, base64, json
from datetime import datetime, timedelta
import httpx

app = FastAPI(title="Maruy Bags API", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

os.makedirs("static/uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="static/uploads"), name="uploads")

# ── SUPABASE ──────────────────────────────────────────────────────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}
def sb_url(table): return f"{SUPABASE_URL}/rest/v1/{table}"

# ── JWT ───────────────────────────────────────────────────────────────────────
JWT_SECRET       = os.getenv("JWT_SECRET", "b073aaec1f47c862ba7257c485fa876d525d14e41188a3d4a134c646492abcb3")
JWT_EXPIRE_HOURS = 24

# ── USUARIOS CON ROLES ────────────────────────────────────────────────────────
# admin     → contraseña: 181025   rol: admin
# empleado  → contraseña: maruy2024  rol: empleado
USUARIOS = {
    "admin":    {"hash": "a59f695f1f36afb77967b0d397293d2fb3b1ab77caa7b3234df80af14313d18d", "rol": "admin"},
    "empleado": {"hash": "538113a0bcd6928907d8c700840c73381a30499aa34216ba7a1126923367ff5f", "rol": "empleado"},
}

# ── JWT PURO ──────────────────────────────────────────────────────────────────
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4: s += '=' * padding
    return base64.urlsafe_b64decode(s)

def crear_jwt(username: str, rol: str) -> str:
    header  = b64url_encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    exp     = int((datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)).timestamp())
    payload = b64url_encode(json.dumps({"sub": username, "rol": rol, "exp": exp, "iat": int(datetime.utcnow().timestamp())}).encode())
    msg     = f"{header}.{payload}".encode()
    sig     = b64url_encode(hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def verificar_jwt(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3: raise ValueError("Token inválido")
        header, payload, sig = parts
        msg      = f"{header}.{payload}".encode()
        sig_calc = b64url_encode(hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest())
        if not hmac.compare_digest(sig, sig_calc): raise ValueError("Firma inválida")
        data = json.loads(b64url_decode(payload))
        if data.get("exp", 0) < int(datetime.utcnow().timestamp()): raise ValueError("Token expirado")
        return data
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# ── DEPENDENCIAS ──────────────────────────────────────────────────────────────
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    return verificar_jwt(credentials.credentials)

def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("rol") != "admin":
        raise HTTPException(status_code=403, detail="Solo administradores pueden realizar esta acción")
    return user

# ── MODELOS ───────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class Producto(BaseModel):
    nombre:      str
    categoria:   str
    precio:      float
    color:       str
    badge:       Optional[str] = None
    descripcion: str
    imagen:      Optional[str] = ""
    stock:       int = 0

class ProductoUpdate(BaseModel):
    nombre:      Optional[str]   = None
    categoria:   Optional[str]   = None
    precio:      Optional[float] = None
    color:       Optional[str]   = None
    badge:       Optional[str]   = None
    descripcion: Optional[str]   = None
    imagen:      Optional[str]   = None
    stock:       Optional[int]   = None

class Pedido(BaseModel):
    cliente_nombre:   str
    cliente_telefono: str
    cliente_ciudad:   Optional[str] = ""
    productos:        List[dict]
    total:            float
    notas:            Optional[str] = ""

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
def login(req: LoginRequest):
    user_data = USUARIOS.get(req.username.lower())
    pwd_hash  = hashlib.sha256(req.password.encode()).hexdigest()
    if not user_data or not hmac.compare_digest(pwd_hash, user_data["hash"]):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    token = crear_jwt(req.username.lower(), user_data["rol"])
    return {
        "access_token": token,
        "token_type":   "bearer",
        "expires_in":   JWT_EXPIRE_HOURS * 3600,
        "username":     req.username.lower(),
        "rol":          user_data["rol"]
    }

@app.get("/api/auth/me")
def me(user: dict = Depends(get_current_user)):
    return {"username": user.get("sub"), "rol": user.get("rol"), "message": "Token válido"}

# ── PRODUCTOS ─────────────────────────────────────────────────────────────────
@app.get("/api/productos")
async def listar_productos(categoria: Optional[str] = None, color: Optional[str] = None):
    url = sb_url("productos") + "?select=*&order=id.asc"
    if categoria: url += f"&categoria=eq.{categoria}"
    if color:     url += f"&color=eq.{color}"
    async with httpx.AsyncClient() as client:
        res = await client.get(url, headers=HEADERS)
    if res.status_code != 200: raise HTTPException(500, "Error obteniendo productos")
    return res.json()

@app.get("/api/productos/{id}")
async def obtener_producto(id: int):
    url = sb_url("productos") + f"?id=eq.{id}&select=*"
    async with httpx.AsyncClient() as client:
        res = await client.get(url, headers=HEADERS)
    data = res.json()
    if not data: raise HTTPException(404, "Producto no encontrado")
    return data[0]

@app.post("/api/productos", status_code=201)
async def crear_producto(producto: Producto, user: dict = Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        res = await client.post(sb_url("productos"), headers=HEADERS, json=producto.dict())
    if res.status_code not in [200, 201]: raise HTTPException(500, "Error creando producto")
    return res.json()[0] if res.json() else producto.dict()

@app.patch("/api/productos/{id}")
async def actualizar_parcial(id: int, cambios: ProductoUpdate, user: dict = Depends(get_current_user)):
    url  = sb_url("productos") + f"?id=eq.{id}"
    data = {k: v for k, v in cambios.dict().items() if v is not None}
    async with httpx.AsyncClient() as client:
        res = await client.patch(url, headers=HEADERS, json=data)
    if res.status_code not in [200, 204]: raise HTTPException(500, "Error actualizando")
    return await obtener_producto(id)

@app.delete("/api/productos/{id}")
async def eliminar_producto(id: int, user: dict = Depends(require_admin)):
    # Solo administradores
    url = sb_url("productos") + f"?id=eq.{id}"
    async with httpx.AsyncClient() as client:
        res = await client.delete(url, headers=HEADERS)
    if res.status_code not in [200, 204]: raise HTTPException(500, "Error eliminando producto")
    return {"mensaje": f"Producto {id} eliminado", "eliminado_por": user.get("sub")}

@app.post("/api/productos/{id}/imagen")
async def subir_imagen(id: int, archivo: UploadFile = File(...), user: dict = Depends(get_current_user)):
    ext = os.path.splitext(archivo.filename)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png", ".webp"]: raise HTTPException(400, "Solo JPG, PNG o WEBP")
    nombre_archivo = f"{uuid.uuid4().hex}{ext}"
    ruta = f"static/uploads/{nombre_archivo}"
    with open(ruta, "wb") as f: shutil.copyfileobj(archivo.file, f)
    base_url  = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:8000")
    url_imagen = f"{base_url}/uploads/{nombre_archivo}"
    await actualizar_parcial(id, ProductoUpdate(imagen=url_imagen), user)
    return {"imagen_url": url_imagen}

# ── PEDIDOS ───────────────────────────────────────────────────────────────────
@app.get("/api/pedidos")
async def listar_pedidos(estado: Optional[str] = None, user: dict = Depends(get_current_user)):
    url = sb_url("pedidos") + "?select=*&order=fecha.desc"
    if estado: url += f"&estado=eq.{estado}"
    async with httpx.AsyncClient() as client:
        res = await client.get(url, headers=HEADERS)
    return res.json()

@app.post("/api/pedidos", status_code=201)
async def crear_pedido(pedido: Pedido):
    nuevo = {"fecha": datetime.now().isoformat(), "estado": "pendiente", **pedido.dict()}
    async with httpx.AsyncClient() as client:
        res = await client.post(sb_url("pedidos"), headers=HEADERS, json=nuevo)
    if res.status_code not in [200, 201]: raise HTTPException(500, "Error creando pedido")
    return res.json()[0] if res.json() else nuevo

@app.patch("/api/pedidos/{id}/estado")
async def cambiar_estado(id: int, estado: str, user: dict = Depends(get_current_user)):
    validos = ["pendiente","confirmado","enviado","entregado","cancelado"]
    if estado not in validos: raise HTTPException(400, f"Estado inválido. Usa: {validos}")
    url = sb_url("pedidos") + f"?id=eq.{id}"
    async with httpx.AsyncClient() as client:
        res = await client.patch(url, headers=HEADERS, json={"estado": estado})
    return {"mensaje": f"Pedido {id} actualizado a {estado}"}

@app.delete("/api/pedidos/{id}")
async def eliminar_pedido(id: int, user: dict = Depends(require_admin)):
    # Solo administradores
    url = sb_url("pedidos") + f"?id=eq.{id}"
    async with httpx.AsyncClient() as client:
        res = await client.delete(url, headers=HEADERS)
    return {"mensaje": f"Pedido {id} eliminado"}

# ── STATS ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def estadisticas(user: dict = Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        p = await client.get(sb_url("productos") + "?select=id,categoria", headers=HEADERS)
        o = await client.get(sb_url("pedidos") + "?select=id,estado,total", headers=HEADERS)
    productos = p.json()
    pedidos   = o.json()
    return {
        "total_productos":    len(productos),
        "total_pedidos":      len(pedidos),
        "pedidos_pendientes": len([x for x in pedidos if x.get("estado") == "pendiente"]),
        "total_ventas":       sum(float(x.get("total",0)) for x in pedidos if x.get("estado") != "cancelado"),
        "categorias":         list(set(x["categoria"] for x in productos)),
    }

@app.get("/")
def root():
    return {"mensaje": "Maruy Bags API v4 — JWT + Roles", "docs": "/docs"}

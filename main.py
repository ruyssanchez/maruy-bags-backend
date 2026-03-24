from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import os, uuid, shutil, hashlib, hmac, base64, json
from datetime import datetime, timedelta
import httpx

app = FastAPI(title="Maruy Bags API", version="5.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

os.makedirs("static/uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="static/uploads"), name="uploads")

# ── SUPABASE ──────────────────────────────────────────────────────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
SB_HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}
def sb(table): return f"{SUPABASE_URL}/rest/v1/{table}"

# ── JWT ───────────────────────────────────────────────────────────────────────
JWT_SECRET       = os.getenv("JWT_SECRET", "b073aaec1f47c862ba7257c485fa876d525d14e41188a3d4a134c646492abcb3")
JWT_EXPIRE_HOURS = 24

def b64e(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
def b64d(s):
    s += '=' * (4 - len(s) % 4) if len(s) % 4 else ''
    return base64.urlsafe_b64decode(s)

def crear_jwt(username: str, rol: str) -> str:
    h = b64e(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    exp = int((datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)).timestamp())
    p = b64e(json.dumps({"sub":username,"rol":rol,"exp":exp}).encode())
    sig = b64e(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"

def verificar_jwt(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3: raise ValueError("Token inválido")
        h, p, sig = parts
        sig_calc = b64e(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, sig_calc): raise ValueError("Firma inválida")
        data = json.loads(b64d(p))
        if data.get("exp", 0) < int(datetime.utcnow().timestamp()): raise ValueError("Token expirado")
        return data
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=401, detail=str(e))

security = HTTPBearer()

def get_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    return verificar_jwt(creds.credentials)

def require_admin(user: dict = Depends(get_user)) -> dict:
    if user.get("rol") != "admin":
        raise HTTPException(403, "Solo administradores pueden realizar esta acción")
    return user

# ── MODELOS ───────────────────────────────────────────────────────────────────
class LoginReq(BaseModel):
    username: str
    password: str

class Producto(BaseModel):
    nombre: str; categoria: str; precio: float; color: str
    badge: Optional[str] = None; descripcion: str
    imagen: Optional[str] = ""; stock: int = 0

class ProductoUpdate(BaseModel):
    nombre: Optional[str]=None; categoria: Optional[str]=None
    precio: Optional[float]=None; color: Optional[str]=None
    badge: Optional[str]=None; descripcion: Optional[str]=None
    imagen: Optional[str]=None; stock: Optional[int]=None

class Pedido(BaseModel):
    cliente_nombre: str; cliente_telefono: str
    cliente_ciudad: Optional[str]=""; productos: List[dict]
    total: float; notas: Optional[str]=""

class UsuarioCreate(BaseModel):
    username: str; password: str
    rol: str  # 'admin' o 'empleado'

class UsuarioUpdate(BaseModel):
    password: Optional[str]=None
    rol: Optional[str]=None
    activo: Optional[bool]=None

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(req: LoginReq):
    pwd_hash = hashlib.sha256(req.password.encode()).hexdigest()
    url = sb("usuarios") + f"?username=eq.{req.username.lower()}&activo=eq.true&select=*"
    async with httpx.AsyncClient() as c:
        res = await c.get(url, headers=SB_HEADERS)
    data = res.json()
    if not data or not hmac.compare_digest(data[0]["password_hash"], pwd_hash):
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    u = data[0]
    token = crear_jwt(u["username"], u["rol"])
    return {"access_token": token, "token_type": "bearer",
            "username": u["username"], "rol": u["rol"],
            "expires_in": JWT_EXPIRE_HOURS * 3600}

@app.get("/api/auth/me")
def me(user: dict = Depends(get_user)):
    return {"username": user.get("sub"), "rol": user.get("rol")}

# ── USUARIOS (solo admin) ─────────────────────────────────────────────────────
@app.get("/api/usuarios")
async def listar_usuarios(user: dict = Depends(require_admin)):
    url = sb("usuarios") + "?select=id,username,rol,activo,creado_en&order=id.asc"
    async with httpx.AsyncClient() as c:
        res = await c.get(url, headers=SB_HEADERS)
    return res.json()

@app.post("/api/usuarios", status_code=201)
async def crear_usuario(nuevo: UsuarioCreate, user: dict = Depends(require_admin)):
    if nuevo.rol not in ["admin", "empleado"]:
        raise HTTPException(400, "Rol inválido. Usa: admin o empleado")
    pwd_hash = hashlib.sha256(nuevo.password.encode()).hexdigest()
    body = {"username": nuevo.username.lower(), "password_hash": pwd_hash, "rol": nuevo.rol, "activo": True}
    async with httpx.AsyncClient() as c:
        res = await c.post(sb("usuarios"), headers=SB_HEADERS, json=body)
    if res.status_code not in [200, 201]:
        raise HTTPException(400, "Error creando usuario (¿usuario ya existe?)")
    return res.json()[0]

@app.patch("/api/usuarios/{id}")
async def actualizar_usuario(id: int, cambios: UsuarioUpdate, user: dict = Depends(require_admin)):
    body = {}
    if cambios.password: body["password_hash"] = hashlib.sha256(cambios.password.encode()).hexdigest()
    if cambios.rol:      body["rol"] = cambios.rol
    if cambios.activo is not None: body["activo"] = cambios.activo
    if not body: raise HTTPException(400, "Sin cambios")
    url = sb("usuarios") + f"?id=eq.{id}"
    async with httpx.AsyncClient() as c:
        res = await c.patch(url, headers=SB_HEADERS, json=body)
    return {"mensaje": "Usuario actualizado"}

@app.delete("/api/usuarios/{id}")
async def eliminar_usuario(id: int, user: dict = Depends(require_admin)):
    # No eliminar, solo desactivar
    url = sb("usuarios") + f"?id=eq.{id}"
    async with httpx.AsyncClient() as c:
        res = await c.patch(url, headers=SB_HEADERS, json={"activo": False})
    return {"mensaje": "Usuario desactivado"}

# ── PRODUCTOS ─────────────────────────────────────────────────────────────────
@app.get("/api/productos")
async def listar_productos(categoria: Optional[str]=None, color: Optional[str]=None):
    url = sb("productos") + "?select=*&order=id.asc"
    if categoria: url += f"&categoria=eq.{categoria}"
    if color:     url += f"&color=eq.{color}"
    async with httpx.AsyncClient() as c:
        res = await c.get(url, headers=SB_HEADERS)
    return res.json()

@app.get("/api/productos/{id}")
async def obtener_producto(id: int):
    async with httpx.AsyncClient() as c:
        res = await c.get(sb("productos")+f"?id=eq.{id}&select=*", headers=SB_HEADERS)
    data = res.json()
    if not data: raise HTTPException(404, "Producto no encontrado")
    return data[0]

@app.post("/api/productos", status_code=201)
async def crear_producto(p: Producto, user: dict = Depends(require_admin)):
    async with httpx.AsyncClient() as c:
        res = await c.post(sb("productos"), headers=SB_HEADERS, json=p.dict())
    if res.status_code not in [200,201]: raise HTTPException(500, "Error creando producto")
    return res.json()[0]

@app.patch("/api/productos/{id}")
async def actualizar_producto(id: int, cambios: ProductoUpdate, user: dict = Depends(get_user)):
    data = {k:v for k,v in cambios.dict().items() if v is not None}
    async with httpx.AsyncClient() as c:
        res = await c.patch(sb("productos")+f"?id=eq.{id}", headers=SB_HEADERS, json=data)
    if res.status_code not in [200,204]: raise HTTPException(500, "Error actualizando")
    return await obtener_producto(id)

@app.delete("/api/productos/{id}")
async def eliminar_producto(id: int, user: dict = Depends(require_admin)):
    async with httpx.AsyncClient() as c:
        res = await c.delete(sb("productos")+f"?id=eq.{id}", headers=SB_HEADERS)
    if res.status_code not in [200,204]: raise HTTPException(500, "Error eliminando")
    return {"mensaje": f"Producto {id} eliminado", "por": user.get("sub")}

@app.post("/api/productos/{id}/imagen")
async def subir_imagen(id: int, archivo: UploadFile = File(...), user: dict = Depends(get_user)):
    ext = os.path.splitext(archivo.filename)[1].lower()
    if ext not in [".jpg",".jpeg",".png",".webp"]: raise HTTPException(400,"Solo JPG,PNG,WEBP")
    nombre = f"{uuid.uuid4().hex}{ext}"
    with open(f"static/uploads/{nombre}", "wb") as f: shutil.copyfileobj(archivo.file, f)
    base_url = os.getenv("RENDER_EXTERNAL_URL","http://localhost:8000")
    url_img = f"{base_url}/uploads/{nombre}"
    await actualizar_producto(id, ProductoUpdate(imagen=url_img), user)
    return {"imagen_url": url_img}

# ── PEDIDOS ───────────────────────────────────────────────────────────────────
@app.get("/api/pedidos")
async def listar_pedidos(estado: Optional[str]=None, user: dict = Depends(get_user)):
    url = sb("pedidos") + "?select=*&order=fecha.desc"
    if estado: url += f"&estado=eq.{estado}"
    async with httpx.AsyncClient() as c:
        res = await c.get(url, headers=SB_HEADERS)
    return res.json()

@app.post("/api/pedidos", status_code=201)
async def crear_pedido(pedido: Pedido):
    nuevo = {"fecha": datetime.now().isoformat(), "estado":"pendiente", **pedido.dict()}
    async with httpx.AsyncClient() as c:
        res = await c.post(sb("pedidos"), headers=SB_HEADERS, json=nuevo)
    if res.status_code not in [200,201]: raise HTTPException(500,"Error creando pedido")
    return res.json()[0] if res.json() else nuevo

@app.patch("/api/pedidos/{id}/estado")
async def cambiar_estado(id: int, estado: str, user: dict = Depends(get_user)):
    validos = ["pendiente","confirmado","enviado","entregado","cancelado"]
    if estado not in validos: raise HTTPException(400,f"Usa: {validos}")
    async with httpx.AsyncClient() as c:
        await c.patch(sb("pedidos")+f"?id=eq.{id}", headers=SB_HEADERS, json={"estado":estado})
    return {"mensaje":f"Pedido {id} → {estado}"}

@app.delete("/api/pedidos/{id}")
async def eliminar_pedido(id: int, user: dict = Depends(require_admin)):
    async with httpx.AsyncClient() as c:
        res = await c.delete(sb("pedidos")+f"?id=eq.{id}", headers=SB_HEADERS)
    if res.status_code not in [200,204]: raise HTTPException(500,"Error eliminando pedido")
    return {"mensaje":f"Pedido {id} eliminado","por":user.get("sub")}

# ── STATS ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def estadisticas(user: dict = Depends(get_user)):
    async with httpx.AsyncClient() as c:
        p = await c.get(sb("productos")+"?select=id,categoria", headers=SB_HEADERS)
        o = await c.get(sb("pedidos")+"?select=id,estado,total", headers=SB_HEADERS)
    prods = p.json(); peds = o.json()
    return {
        "total_productos":    len(prods),
        "total_pedidos":      len(peds),
        "pedidos_pendientes": len([x for x in peds if x.get("estado")=="pendiente"]),
        "total_ventas":       sum(float(x.get("total",0)) for x in peds if x.get("estado")!="cancelado"),
        "categorias":         list(set(x["categoria"] for x in prods)),
    }

@app.get("/")
def root(): return {"mensaje":"Maruy Bags API v5 — JWT + Roles + Usuarios Supabase","docs":"/docs"}

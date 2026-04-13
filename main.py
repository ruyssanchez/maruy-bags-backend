from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import os, uuid, shutil, hashlib, hmac, base64, json
from datetime import datetime, timedelta
import httpx

app = FastAPI(title="Maruy Bags API", version="6.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://maruybags.netlify.app",
        "https://catalogomaruy.netlify.app",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ],
    allow_credentials=False,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["Authorization","Content-Type"],
    expose_headers=["*"],
    max_age=3600,
)

# Middleware de headers de seguridad
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["X-XSS-Protection"]       = "1; mode=block"
        response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)

os.makedirs("static/uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="static/uploads"), name="uploads")

# ── SUPABASE ──────────────────────────────────────────────────────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
SB = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}
def sb(t): return f"{SUPABASE_URL}/rest/v1/{t}"

# ── JWT ───────────────────────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "b073aaec1f47c862ba7257c485fa876d525d14e41188a3d4a134c646492abcb3")
JWT_HOURS  = 24

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
    nombre:      str
    categoria:   str
    precio:      float
    color:       str
    badge:       Optional[str] = None
    descripcion: str
    imagenes:    Optional[List[str]] = []
    stock:       int = 0

    class Config:
        # Validaciones de seguridad
        @staticmethod
        def schema_extra(values):
            return values

    def __init__(self, **data):
        # Sanitizar y limitar longitud de campos de texto
        if 'nombre' in data and data['nombre']:
            data['nombre'] = str(data['nombre'])[:200].strip()
        if 'descripcion' in data and data['descripcion']:
            data['descripcion'] = str(data['descripcion'])[:2000].strip()
        if 'color' in data and data['color']:
            data['color'] = str(data['color'])[:100].strip()
        if 'badge' in data and data['badge']:
            data['badge'] = str(data['badge'])[:50].strip()
        if 'precio' in data:
            p = float(data['precio'] or 0)
            if p < 0 or p > 100_000_000:
                raise ValueError("Precio fuera de rango")
            data['precio'] = p
        if 'stock' in data:
            s = int(data['stock'] or 0)
            if s < 0 or s > 1_000_000:
                raise ValueError("Stock fuera de rango")
            data['stock'] = s
        if 'imagenes' in data and data['imagenes']:
            # Validar URLs de imágenes
            ALLOWED = ['maruy-bags-backend.onrender.com','pzdzexwntjreaxahtwvi.supabase.co']
            safe = []
            for url in data['imagenes'][:20]:  # máximo 20 imágenes
                if not url: continue
                try:
                    from urllib.parse import urlparse
                    p = urlparse(str(url))
                    if p.scheme == 'https' and any(h in p.netloc for h in ALLOWED):
                        safe.append(str(url)[:500])
                    elif str(url).startswith('data:image/'):
                        safe.append(str(url)[:500000])  # base64 ok, límite 500KB
                except:
                    pass
            data['imagenes'] = safe
        super().__init__(**data)

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
    pwd_hash = hashlib.sha256(req.password.encode()).hexdigest()
    url = sb("usuarios") + f"?username=eq.{req.username.lower()}&activo=eq.true&select=*"
    async with httpx.AsyncClient() as c:
        res = await c.get(url, headers=SB)
    data = res.json()
    if not data or not hmac.compare_digest(data[0]["password_hash"], pwd_hash):
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    u = data[0]
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
    # Validar username
    import re as _re
    if not _re.match(r'^[a-z0-9_]{3,30}$', nuevo.username.lower()):
        raise HTTPException(400,"Usuario inválido: 3-30 caracteres, solo letras minúsculas, números y _")
    # Validar longitud contraseña
    if len(nuevo.password) < 6 or len(nuevo.password) > 128:
        raise HTTPException(400,"Contraseña debe tener entre 6 y 128 caracteres")
    pwd_hash = hashlib.sha256(nuevo.password.encode()).hexdigest()
    body = {"username": nuevo.username.lower(), "password_hash": pwd_hash, "rol": nuevo.rol, "activo": True}
    async with httpx.AsyncClient() as c:
        res = await c.post(sb("usuarios"), headers=SB, json=body)
    if res.status_code not in [200,201]: raise HTTPException(400,"Error creando usuario (¿ya existe?)")
    return res.json()[0]

@app.patch("/api/usuarios/{id}")
async def actualizar_usuario(id: int, cambios: UsuarioUpdate, u: dict = Depends(require_admin)):
    body = {}
    if cambios.password: body["password_hash"] = hashlib.sha256(cambios.password.encode()).hexdigest()
    if cambios.rol:      body["rol"] = cambios.rol
    if cambios.activo is not None: body["activo"] = cambios.activo
    if not body: raise HTTPException(400,"Sin cambios")
    async with httpx.AsyncClient() as c:
        await c.patch(sb("usuarios")+f"?id=eq.{id}", headers=SB, json=body)
    return {"mensaje": "Usuario actualizado"}

@app.delete("/api/usuarios/{id}")
async def eliminar_usuario(id: int, u: dict = Depends(require_admin)):
    # Verificar que no se elimine a sí mismo
    async with httpx.AsyncClient() as c:
        res = await c.get(sb("usuarios")+f"?id=eq.{id}&select=username", headers=SB)
    data = res.json()
    if data and data[0]["username"] == u.get("sub"):
        raise HTTPException(400, "No puedes eliminar tu propio usuario")
    async with httpx.AsyncClient() as c:
        res = await c.delete(sb("usuarios")+f"?id=eq.{id}", headers=SB)
    if res.status_code not in [200,204]: raise HTTPException(500,"Error eliminando usuario")
    return {"mensaje": f"Usuario {id} eliminado permanentemente"}

# ── PRODUCTOS ─────────────────────────────────────────────────────────────────
@app.get("/api/productos")
async def listar_productos(categoria: Optional[str]=None, color: Optional[str]=None):
    url = sb("productos") + "?select=*&order=id.asc"
    if categoria: url += f"&categoria=eq.{categoria}"
    if color:     url += f"&color=eq.{color}"
    async with httpx.AsyncClient() as c:
        res = await c.get(url, headers=SB)
    if res.status_code != 200: raise HTTPException(500,"Error obteniendo productos")
    productos = res.json()
    # Normalizar: asegurar que imagenes sea siempre una lista
    for p in productos:
        if "imagenes" not in p or not p["imagenes"]:
            # Compatibilidad con campo imagen antiguo
            img = p.get("imagen","")
            p["imagenes"] = [img] if img else []
    return productos

@app.get("/api/productos/{id}")
async def obtener_producto(id: int):
    async with httpx.AsyncClient() as c:
        res = await c.get(sb("productos")+f"?id=eq.{id}&select=*", headers=SB)
    data = res.json()
    if not data: raise HTTPException(404,"Producto no encontrado")
    p = data[0]
    if "imagenes" not in p or not p["imagenes"]:
        img = p.get("imagen","")
        p["imagenes"] = [img] if img else []
    return p

@app.post("/api/productos", status_code=201)
async def crear_producto(p: Producto, u: dict = Depends(require_admin)):
    body = p.dict()
    # imagenes como array JSON
    body["imagenes"] = p.imagenes or []
    async with httpx.AsyncClient() as c:
        res = await c.post(sb("productos"), headers=SB, json=body)
    if res.status_code not in [200,201]: raise HTTPException(500,"Error creando producto")
    return res.json()[0]

@app.patch("/api/productos/{id}")
async def actualizar_producto(id: int, cambios: ProductoUpdate, u: dict = Depends(get_user)):
    data = {}
    for k, v in cambios.dict().items():
        if v is not None:
            data[k] = v
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
    if ext not in [".jpg",".jpeg",".png",".webp"]:
        raise HTTPException(400, "Solo JPG, PNG o WEBP")

    # Validar tamaño máximo: 5MB
    MAX_SIZE = 5 * 1024 * 1024
    contenido = await archivo.read()
    if len(contenido) > MAX_SIZE:
        raise HTTPException(400, "Imagen demasiado grande. Máximo 5MB")

    # Nombre único para la imagen
    nombre = f"{uuid.uuid4().hex}{ext}"

    # ── SUBIR A SUPABASE STORAGE (persistente, no se borra) ──────────────────
    # El bucket "imagenes-productos" ya existe en tu Supabase
    storage_url = f"{SUPABASE_URL}/storage/v1/object/imagenes-productos/{nombre}"
    content_type_map = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp"
    }
    content_type = content_type_map.get(ext, "image/jpeg")

    storage_headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": content_type,
        "x-upsert": "true"  # Sobrescribir si existe
    }

    async with httpx.AsyncClient() as c:
        res = await c.post(storage_url, content=contenido, headers=storage_headers)

    if res.status_code not in [200, 201]:
        # Fallback: guardar localmente si Supabase falla
        with open(f"static/uploads/{nombre}", "wb") as f:
            f.write(contenido)
        base_url = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:8000")
        url_img = f"{base_url}/uploads/{nombre}"
    else:
        # URL pública de Supabase Storage — permanente ✅
        url_img = f"{SUPABASE_URL}/storage/v1/object/public/imagenes-productos/{nombre}"

    # Agregar a la lista de imágenes existente del producto
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
    if estado not in validos: raise HTTPException(400,f"Usa: {validos}")
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
def root(): return {"mensaje":"Maruy Bags API v6","docs":"/docs"}

# ── CONFIGURACIÓN DE ENVÍOS (editable desde admin) ────────────────────────────
class ConfigEnvio(BaseModel):
    local_precio: float = 12000
    local_ciudades: str = "Barranquilla,Soledad,Malambo,Galapa,Puerto Colombia"
    inter_local: float = 12000
    inter_regional: float = 25000
    inter_nacional: float = 25000
    inter_especial: float = 25000
    coord_local: float = 12000
    coord_regional: float = 20000
    coord_nacional: float = 23000
    coord_especial: float = 30000

DEFAULT_CONFIG = {
    "local_precio": 12000,
    "local_ciudades": "Barranquilla,Soledad,Malambo,Galapa,Puerto Colombia",
    "inter_local": 12000, "inter_regional": 25000,
    "inter_nacional": 25000, "inter_especial": 25000,
    "coord_local": 12000, "coord_regional": 20000,
    "coord_nacional": 23000, "coord_especial": 30000
}

@app.get("/api/config/envio")
async def get_config_envio():
    """Configuración pública de tarifas de envío"""
    try:
        async with httpx.AsyncClient() as c:
            res = await c.get(
                f"{SUPABASE_URL}/rest/v1/configuracion?clave=eq.envio_tarifas&select=valor",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
            )
        if res.status_code == 200:
            data = res.json()
            if data and len(data) > 0:
                import json as _json
                return _json.loads(data[0]["valor"])
    except Exception:
        pass
    return DEFAULT_CONFIG

@app.put("/api/config/envio")
async def update_config_envio(config: ConfigEnvio, u: dict = Depends(require_admin)):
    """Actualizar tarifas de envío - solo admin"""
    import json as _json
    valor = _json.dumps(config.dict())
    async with httpx.AsyncClient() as c:
        # Try upsert
        res = await c.post(
            f"{SUPABASE_URL}/rest/v1/configuracion",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates"
            },
            content=_json.dumps({"clave": "envio_tarifas", "valor": valor})
        )
    if res.status_code not in [200, 201]:
        raise HTTPException(500, "Error guardando configuración")
    return {"ok": True, "config": config.dict()}

# ── PEDIDOS WHATSAPP (registro cuando cliente va a WA) ─────────────────────────
class PedidoWA(BaseModel):
    producto_id: int
    producto_nombre: str
    producto_precio: float
    cliente_nombre: str
    cliente_telefono: str
    cliente_ciudad: str
    cliente_departamento: str = ""
    cliente_direccion: str
    cliente_cedula: str = ""
    cliente_notas: str = ""
    transportadora: str = ""
    envio_precio: float = 0
    total: float = 0

@app.post("/api/pedidos/whatsapp")
async def registrar_pedido_wa(pedido: PedidoWA):
    """Registrar pedido cuando cliente da clic en WhatsApp - público"""
    import json as _json
    # Validaciones de seguridad
    if not (0 < pedido.producto_id < 1_000_000):
        raise HTTPException(400, "ID inválido")
    if not (0 <= pedido.producto_precio <= 200_000):
        raise HTTPException(400, "Precio inválido")
    if not (0 <= pedido.envio_precio <= 100_000):
        raise HTTPException(400, "Envío inválido")
    if len(pedido.cliente_nombre) > 80:
        raise HTTPException(400, "Nombre muy largo")
    if pedido.cliente_cedula and not pedido.cliente_cedula.isdigit():
        raise HTTPException(400, "Cédula inválida")

    data = {
        "cliente_nombre": pedido.cliente_nombre[:80],
        "cliente_telefono": pedido.cliente_telefono[:20],
        "cliente_ciudad": f"{pedido.cliente_departamento} - {pedido.cliente_ciudad}"[:100],
        "productos": _json.dumps([{
            "id": pedido.producto_id,
            "nombre": pedido.producto_nombre[:100],
            "precio": pedido.producto_precio,
            "cantidad": 1
        }]),
        "total": pedido.total,
        "notas": f"Dir: {pedido.cliente_direccion[:100]} | Ced: {pedido.cliente_cedula} | Transp: {pedido.transportadora} | Envío: ${pedido.envio_precio} | {pedido.cliente_notas[:100]}"
    }

    async with httpx.AsyncClient() as c:
        res = await c.post(
            f"{SUPABASE_URL}/rest/v1/pedidos",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=representation"
            },
            content=_json.dumps(data)
        )
    if res.status_code not in [200, 201]:
        raise HTTPException(500, "Error registrando pedido")
    return {"ok": True}

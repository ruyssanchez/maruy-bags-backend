from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List
import os, uuid, shutil
from datetime import datetime
import httpx

app = FastAPI(title="Maruy Bags API", version="2.0.0")

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

# ── SUPABASE — se leen desde variables de entorno en Render ───────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

def sb_url(table):
    return f"{SUPABASE_URL}/rest/v1/{table}"

# ── MODELOS ───────────────────────────────────────────────────────────────────
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

# ── PRODUCTOS ─────────────────────────────────────────────────────────────────
@app.get("/api/productos")
async def listar_productos(categoria: Optional[str] = None, color: Optional[str] = None):
    url = sb_url("productos") + "?select=*&order=id.asc"
    if categoria: url += f"&categoria=eq.{categoria}"
    if color:     url += f"&color=eq.{color}"
    async with httpx.AsyncClient() as client:
        res = await client.get(url, headers=HEADERS)
    if res.status_code != 200:
        raise HTTPException(500, "Error obteniendo productos")
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
async def crear_producto(producto: Producto):
    async with httpx.AsyncClient() as client:
        res = await client.post(sb_url("productos"), headers=HEADERS, json=producto.dict())
    if res.status_code not in [200, 201]: raise HTTPException(500, "Error creando producto")
    return res.json()[0] if res.json() else producto.dict()

@app.put("/api/productos/{id}")
async def actualizar_producto(id: int, producto: Producto):
    url = sb_url("productos") + f"?id=eq.{id}"
    async with httpx.AsyncClient() as client:
        res = await client.put(url, headers=HEADERS, json=producto.dict())
    if res.status_code not in [200, 204]: raise HTTPException(500, "Error actualizando")
    return await obtener_producto(id)

@app.patch("/api/productos/{id}")
async def actualizar_parcial(id: int, cambios: ProductoUpdate):
    url = sb_url("productos") + f"?id=eq.{id}"
    data = {k: v for k, v in cambios.dict().items() if v is not None}
    async with httpx.AsyncClient() as client:
        res = await client.patch(url, headers=HEADERS, json=data)
    if res.status_code not in [200, 204]: raise HTTPException(500, "Error actualizando")
    return await obtener_producto(id)

@app.delete("/api/productos/{id}")
async def eliminar_producto(id: int):
    url = sb_url("productos") + f"?id=eq.{id}"
    async with httpx.AsyncClient() as client:
        res = await client.delete(url, headers=HEADERS)
    return {"mensaje": f"Producto {id} eliminado"}

@app.post("/api/productos/{id}/imagen")
async def subir_imagen(id: int, archivo: UploadFile = File(...)):
    ext = os.path.splitext(archivo.filename)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png", ".webp"]:
        raise HTTPException(400, "Solo JPG, PNG o WEBP")
    nombre_archivo = f"{uuid.uuid4().hex}{ext}"
    ruta = f"static/uploads/{nombre_archivo}"
    with open(ruta, "wb") as f:
        shutil.copyfileobj(archivo.file, f)
    base_url = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:8000")
    url_imagen = f"{base_url}/uploads/{nombre_archivo}"
    await actualizar_parcial(id, ProductoUpdate(imagen=url_imagen))
    return {"imagen_url": url_imagen}

# ── PEDIDOS ───────────────────────────────────────────────────────────────────
@app.get("/api/pedidos")
async def listar_pedidos(estado: Optional[str] = None):
    url = sb_url("pedidos") + "?select=*&order=fecha.desc"
    if estado: url += f"&estado=eq.{estado}"
    async with httpx.AsyncClient() as client:
        res = await client.get(url, headers=HEADERS)
    return res.json()

@app.get("/api/pedidos/{id}")
async def obtener_pedido(id: int):
    url = sb_url("pedidos") + f"?id=eq.{id}&select=*"
    async with httpx.AsyncClient() as client:
        res = await client.get(url, headers=HEADERS)
    data = res.json()
    if not data: raise HTTPException(404, "Pedido no encontrado")
    return data[0]

@app.post("/api/pedidos", status_code=201)
async def crear_pedido(pedido: Pedido):
    nuevo = {"fecha": datetime.now().isoformat(), "estado": "pendiente", **pedido.dict()}
    async with httpx.AsyncClient() as client:
        res = await client.post(sb_url("pedidos"), headers=HEADERS, json=nuevo)
    if res.status_code not in [200, 201]: raise HTTPException(500, "Error creando pedido")
    return res.json()[0] if res.json() else nuevo

@app.patch("/api/pedidos/{id}/estado")
async def cambiar_estado(id: int, estado: str):
    validos = ["pendiente","confirmado","enviado","entregado","cancelado"]
    if estado not in validos: raise HTTPException(400, f"Estado inválido. Usa: {validos}")
    url = sb_url("pedidos") + f"?id=eq.{id}"
    async with httpx.AsyncClient() as client:
        res = await client.patch(url, headers=HEADERS, json={"estado": estado})
    return await obtener_pedido(id)

@app.delete("/api/pedidos/{id}")
async def eliminar_pedido(id: int):
    url = sb_url("pedidos") + f"?id=eq.{id}"
    async with httpx.AsyncClient() as client:
        res = await client.delete(url, headers=HEADERS)
    return {"mensaje": f"Pedido {id} eliminado"}

# ── STATS ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def estadisticas():
    async with httpx.AsyncClient() as client:
        p = await client.get(sb_url("productos") + "?select=id,categoria", headers=HEADERS)
        o = await client.get(sb_url("pedidos") + "?select=id,estado,total", headers=HEADERS)
    productos = p.json()
    pedidos   = o.json()
    total_ventas = sum(float(x.get("total",0)) for x in pedidos if x.get("estado") != "cancelado")
    return {
        "total_productos":    len(productos),
        "total_pedidos":      len(pedidos),
        "pedidos_pendientes": len([x for x in pedidos if x.get("estado") == "pendiente"]),
        "total_ventas":       total_ventas,
        "categorias":         list(set(x["categoria"] for x in productos)),
    }

@app.get("/")
def root():
    return {"mensaje": "Maruy Bags API con Supabase", "docs": "/docs"}

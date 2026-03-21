from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List
import json, os, shutil, uuid
from datetime import datetime

app = FastAPI(title="Maruy Bags API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Carpeta de uploads
os.makedirs("static/uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="static/uploads"), name="uploads")

PRODUCTOS_FILE = "data/productos.json"
PEDIDOS_FILE   = "data/pedidos.json"

# Asegura que los archivos JSON existan
def init_data():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(PRODUCTOS_FILE):
        guardar_json(PRODUCTOS_FILE, [
            {"id":1,"nombre":"Bolso Coco Pequeño Kakhi","categoria":"Carteras","precio":105000,"color":"beige","badge":"Nuevo","descripcion":"Bolso compacto de cuero sintético en tono kakhi. Cierre magnético, correa desmontable ajustable y bolsillo interior.","imagen":"https://images.unsplash.com/photo-1590874103328-eac38a683ce7?w=500&q=80","stock":10},
            {"id":2,"nombre":"Bolso Coco Pequeño Negro","categoria":"Carteras","precio":105000,"color":"negro","badge":None,"descripcion":"Clásico en negro. Diseño compacto y funcional, perfecto para el día a día.","imagen":"https://images.unsplash.com/photo-1548036328-c9fa89d128fa?w=500&q=80","stock":8},
            {"id":3,"nombre":"Tula Martina Marrón","categoria":"Manos libres","precio":85000,"color":"café","badge":"Favorito","descripcion":"Tula cruzada en cuero marrón. Liviana, espaciosa y con bolsillo trasero de seguridad.","imagen":"https://images.unsplash.com/photo-1614179818511-b35e6e8ab47e?w=500&q=80","stock":5},
            {"id":4,"nombre":"Bolso Yoko Kakhi","categoria":"Tipo Baguette","precio":105000,"color":"beige","badge":"Nuevo","descripcion":"Baguette alargado estilo parisino. Cierre con cremallera y asa de cadena dorada.","imagen":"https://images.unsplash.com/photo-1627123424574-724758594e93?w=500&q=80","stock":6},
            {"id":5,"nombre":"Bolso Aida Rosado","categoria":"Carteras","precio":105000,"color":"rosado","badge":"Favorito","descripcion":"Diseño suave en rosado pastel. Para looks románticos y frescos.","imagen":"https://images.unsplash.com/photo-1563904092230-7ec217b65fe2?w=500&q=80","stock":4},
            {"id":6,"nombre":"Billetera Minimal Café","categoria":"Billeteras","precio":45000,"color":"café","badge":None,"descripcion":"Billetera slim en cuero genuino. Espacio para 6 tarjetas y billetes.","imagen":"https://images.unsplash.com/photo-1601592998267-b50fa12e89ca?w=500&q=80","stock":12}
        ])
    if not os.path.exists(PEDIDOS_FILE):
        guardar_json(PEDIDOS_FILE, [])

def leer_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def guardar_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def next_id(lista):
    return max((item["id"] for item in lista), default=0) + 1

init_data()

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
def listar_productos(categoria: Optional[str] = None, color: Optional[str] = None):
    p = leer_json(PRODUCTOS_FILE)
    if categoria: p = [x for x in p if x["categoria"].lower() == categoria.lower()]
    if color:     p = [x for x in p if x["color"].lower() == color.lower()]
    return p

@app.get("/api/productos/{id}")
def obtener_producto(id: int):
    prod = next((p for p in leer_json(PRODUCTOS_FILE) if p["id"] == id), None)
    if not prod: raise HTTPException(404, "Producto no encontrado")
    return prod

@app.post("/api/productos", status_code=201)
def crear_producto(producto: Producto):
    productos = leer_json(PRODUCTOS_FILE)
    nuevo = {"id": next_id(productos), **producto.dict()}
    productos.append(nuevo)
    guardar_json(PRODUCTOS_FILE, productos)
    return nuevo

@app.put("/api/productos/{id}")
def actualizar_producto(id: int, producto: Producto):
    productos = leer_json(PRODUCTOS_FILE)
    idx = next((i for i, p in enumerate(productos) if p["id"] == id), None)
    if idx is None: raise HTTPException(404, "Producto no encontrado")
    productos[idx] = {"id": id, **producto.dict()}
    guardar_json(PRODUCTOS_FILE, productos)
    return productos[idx]

@app.patch("/api/productos/{id}")
def actualizar_parcial(id: int, cambios: ProductoUpdate):
    productos = leer_json(PRODUCTOS_FILE)
    idx = next((i for i, p in enumerate(productos) if p["id"] == id), None)
    if idx is None: raise HTTPException(404, "Producto no encontrado")
    for campo, valor in cambios.dict(exclude_none=True).items():
        productos[idx][campo] = valor
    guardar_json(PRODUCTOS_FILE, productos)
    return productos[idx]

@app.delete("/api/productos/{id}")
def eliminar_producto(id: int):
    productos = leer_json(PRODUCTOS_FILE)
    nuevos = [p for p in productos if p["id"] != id]
    if len(nuevos) == len(productos): raise HTTPException(404, "Producto no encontrado")
    guardar_json(PRODUCTOS_FILE, nuevos)
    return {"mensaje": f"Producto {id} eliminado"}

@app.post("/api/productos/{id}/imagen")
async def subir_imagen(id: int, archivo: UploadFile = File(...)):
    productos = leer_json(PRODUCTOS_FILE)
    idx = next((i for i, p in enumerate(productos) if p["id"] == id), None)
    if idx is None: raise HTTPException(404, "Producto no encontrado")
    ext = os.path.splitext(archivo.filename)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png", ".webp"]:
        raise HTTPException(400, "Solo JPG, PNG o WEBP")
    nombre_archivo = f"{uuid.uuid4().hex}{ext}"
    ruta = f"static/uploads/{nombre_archivo}"
    with open(ruta, "wb") as f:
        shutil.copyfileobj(archivo.file, f)
    # En producción usa la URL de Render
    base_url = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:8000")
    url_imagen = f"{base_url}/uploads/{nombre_archivo}"
    productos[idx]["imagen"] = url_imagen
    guardar_json(PRODUCTOS_FILE, productos)
    return {"imagen_url": url_imagen, "producto": productos[idx]}

# ── PEDIDOS ───────────────────────────────────────────────────────────────────
@app.get("/api/pedidos")
def listar_pedidos(estado: Optional[str] = None):
    pedidos = leer_json(PEDIDOS_FILE)
    if estado: pedidos = [p for p in pedidos if p.get("estado","").lower() == estado.lower()]
    return sorted(pedidos, key=lambda x: x.get("fecha",""), reverse=True)

@app.get("/api/pedidos/{id}")
def obtener_pedido(id: int):
    pedido = next((p for p in leer_json(PEDIDOS_FILE) if p["id"] == id), None)
    if not pedido: raise HTTPException(404, "Pedido no encontrado")
    return pedido

@app.post("/api/pedidos", status_code=201)
def crear_pedido(pedido: Pedido):
    pedidos = leer_json(PEDIDOS_FILE)
    nuevo = {"id": next_id(pedidos), "fecha": datetime.now().isoformat(), "estado": "pendiente", **pedido.dict()}
    pedidos.append(nuevo)
    guardar_json(PEDIDOS_FILE, pedidos)
    return nuevo

@app.patch("/api/pedidos/{id}/estado")
def cambiar_estado(id: int, estado: str):
    validos = ["pendiente","confirmado","enviado","entregado","cancelado"]
    if estado not in validos: raise HTTPException(400, f"Estado inválido. Usa: {validos}")
    pedidos = leer_json(PEDIDOS_FILE)
    idx = next((i for i, p in enumerate(pedidos) if p["id"] == id), None)
    if idx is None: raise HTTPException(404, "Pedido no encontrado")
    pedidos[idx]["estado"] = estado
    guardar_json(PEDIDOS_FILE, pedidos)
    return pedidos[idx]

@app.delete("/api/pedidos/{id}")
def eliminar_pedido(id: int):
    pedidos = leer_json(PEDIDOS_FILE)
    nuevos = [p for p in pedidos if p["id"] != id]
    if len(nuevos) == len(pedidos): raise HTTPException(404, "Pedido no encontrado")
    guardar_json(PEDIDOS_FILE, nuevos)
    return {"mensaje": f"Pedido {id} eliminado"}

# ── STATS ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
def estadisticas():
    productos = leer_json(PRODUCTOS_FILE)
    pedidos   = leer_json(PEDIDOS_FILE)
    return {
        "total_productos":    len(productos),
        "total_pedidos":      len(pedidos),
        "pedidos_pendientes": len([p for p in pedidos if p.get("estado") == "pendiente"]),
        "total_ventas":       sum(p["total"] for p in pedidos if p.get("estado") != "cancelado"),
        "categorias":         list(set(p["categoria"] for p in productos)),
    }

@app.get("/")
def root():
    return {"mensaje": "🛍️ Maruy Bags API en línea", "docs": "/docs"}

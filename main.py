import os
from datetime import date, datetime, timedelta
import secrets
from typing import Optional, List

import mysql.connector
from mysql.connector import pooling
from dotenv import load_dotenv
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr, Field
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware

# --- CONFIGURACIÓN ---
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
ALGORITHM = "HS256"
TOKEN_HORAS = 24
_hasher = PasswordHasher()

_pool = pooling.MySQLConnectionPool(
    pool_name="gymfit_pool",
    pool_size=5,
    host=os.getenv("DB_HOST", "127.0.0.1"),
    port=int(os.getenv("DB_PORT", 3306)),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASS", ""),
    database=os.getenv("DB_NAME", "gymfit"),
)

def get_db():
    conn = _pool.get_connection()
    try:
        yield conn
    finally:
        conn.close()

# --- SEGURIDAD ---
def hashear(contrasena: str) -> str:
    return _hasher.hash(contrasena)

def verificar(contrasena: str, hash_guardado: str) -> bool:
    try:
        return _hasher.verify(hash_guardado, contrasena)
    except (VerifyMismatchError, VerificationError):
        return False

def crear_token(id_usuario: int, rol: str) -> str:
    payload = {"sub": str(id_usuario), "rol": rol, "exp": datetime.utcnow() + timedelta(hours=TOKEN_HORAS)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decodificar_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

# --- DEPENDENCIAS ---
bearer = HTTPBearer(auto_error=False)

def usuario_actual(creds: HTTPAuthorizationCredentials | None = Depends(bearer), db=Depends(get_db)) -> dict:
    if not creds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token requerido")
    payload = decodificar_token(creds.credentials)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido")

    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT u.id_usuario, u.nombres, u.apellidos, u.correo, u.telefono, u.estado, r.nombre AS rol
        FROM usuarios u JOIN roles r ON r.id_rol = u.id_rol WHERE u.id_usuario = %s
    """, (payload["sub"],))
    usuario = cur.fetchone()
    cur.close()
    if not usuario or usuario["estado"] != "activo":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario no válido")
    return usuario

def requiere_rol(*roles: str):
    def _check(u: dict = Depends(usuario_actual)) -> dict:
        if u["rol"] not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Sin permisos")
        return u
    return _check

# --- ESQUEMAS ---
class LoginIn(BaseModel):
    correo: EmailStr
    contrasena: str

class RegistroIn(BaseModel):
    nombres: str = Field(..., min_length=2, max_length=50)
    apellidos: str = Field(..., min_length=2, max_length=50)
    tipo_documento: str
    numero_documento: str
    fecha_nacimiento: str
    sexo_genero: Optional[str] = None
    correo: EmailStr
    telefono: str
    contrasena: str
    confirmar_contrasena: str
    id_objetivo: int
    id_plan: int
    nivel_experiencia: str = "principiante"
    lesiones_condiciones: Optional[str] = None
    contacto_emergencia_nombre: Optional[str] = None
    contacto_emergencia_telefono: Optional[str] = None
    acepto_terminos: bool

class PagoSimuladoIn(BaseModel):
    id_membresia: int

class RutinaCompletadaIn(BaseModel):
    nombre_rutina: str

class CrearRutinaIn(BaseModel):
    nombre: str
    descripcion: str
    nivel: str
    ejercicios: List[int]

class AsignarRutinaIn(BaseModel):
    id_rutina: int
    id_cliente: int

# --- APP Y RUTAS ---
app = FastAPI(title="GymFit API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def root():
    return {"mensaje": "GymFit API funcionando", "docs": "/docs"}

# --- AUTENTICACIÓN ---
@app.post("/api/login")
def login(datos: LoginIn, db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT u.*, r.nombre AS rol FROM usuarios u JOIN roles r ON r.id_rol = u.id_rol WHERE u.correo = %s", (datos.correo.lower(),))
    u = cur.fetchone()
    if not u or not verificar(datos.contrasena, u["contrasena_hash"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales incorrectas")
    if u["estado"] != "activo":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cuenta no activa")

    token = crear_token(u["id_usuario"], u["rol"])
    resp = {
        "access_token": token, "token_type": "bearer",
        "usuario": {"id_usuario": u["id_usuario"], "nombres": u["nombres"], "apellidos": u["apellidos"], "correo": u["correo"], "rol": u["rol"]},
        "rol": u["rol"], "acceso_dashboard": False,
    }

    if u["rol"] == "cliente":
        cur.execute("""
            SELECT m.id_membresia, m.estado, m.fecha_fin, p.id_plan,
                   p.nombre AS plan_nombre, p.precio, p.duracion_dias
            FROM clientes c
            JOIN membresias m ON m.id_cliente = c.id_cliente
            JOIN planes p ON p.id_plan = m.id_plan
            WHERE c.id_usuario = %s
            ORDER BY m.creado_en DESC LIMIT 1
        """, (u["id_usuario"],))
        m = cur.fetchone()
        if m:
            cur.execute("""
                SELECT b.codigo
                FROM plan_beneficios pb
                JOIN beneficios b ON b.id_beneficio = pb.id_beneficio
                WHERE pb.id_plan = %s AND pb.incluido = 1
            """, (m["id_plan"],))
            beneficios = [fila["codigo"] for fila in cur.fetchall()]

            resp["id_membresia"] = m["id_membresia"]
            resp["estado_membresia"] = m["estado"]
            resp["fecha_fin"] = str(m["fecha_fin"])
            resp["plan"] = {
                "nombre": m["plan_nombre"],
                "precio": float(m["precio"]),
                "duracion_dias": m["duracion_dias"],
                "beneficios": beneficios
            }
            resp["membresia"] = {
                "id_membresia": m["id_membresia"],
                "estado": m["estado"],
                "fecha_fin": str(m["fecha_fin"]),
                "plan": resp["plan"]
            }
            resp["acceso_dashboard"] = (m["estado"] == "activa" and m["fecha_fin"] >= date.today())
    cur.close()
    return resp

@app.post("/api/registro", status_code=201)
def registro(datos: RegistroIn, db=Depends(get_db)):
    if datos.contrasena != datos.confirmar_contrasena:
        raise HTTPException(400, "Las contraseñas no coinciden")
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id_usuario FROM usuarios WHERE correo=%s OR numero_documento=%s", (datos.correo.lower(), datos.numero_documento))
        if cur.fetchone(): raise HTTPException(409, "Correo o documento ya registrado")

        cur.execute("INSERT INTO usuarios (id_rol, nombres, apellidos, tipo_documento, numero_documento, correo, telefono, fecha_nacimiento, sexo_genero, contrasena_hash, estado) VALUES (2, %s,%s,%s,%s,%s,%s,%s,%s,%s,'activo')", (datos.nombres, datos.apellidos, datos.tipo_documento, datos.numero_documento, datos.correo.lower(), datos.telefono, datos.fecha_nacimiento, datos.sexo_genero, hashear(datos.contrasena)))
        id_usuario = cur.lastrowid

        cur.execute("INSERT INTO clientes (id_usuario, id_objetivo, nivel_experiencia, lesiones_condiciones, acepto_terminos, fecha_aceptacion_terminos, contacto_emergencia_nombre, contacto_emergencia_telefono) VALUES (%s,%s,%s,%s,%s,NOW(),%s,%s)", (id_usuario, datos.id_objetivo, datos.nivel_experiencia, datos.lesiones_condiciones, 1 if datos.acepto_terminos else 0, datos.contacto_emergencia_nombre, datos.contacto_emergencia_telefono))
        id_cliente = cur.lastrowid

        cur.execute("SELECT duracion_dias FROM planes WHERE id_plan=%s", (datos.id_plan,))
        plan = cur.fetchone()
        if not plan: raise HTTPException(400, "Plan no existe")
        fecha_inicio = date.today()
        fecha_fin = fecha_inicio + timedelta(days=plan["duracion_dias"])
        
        cur.execute("INSERT INTO membresias (id_cliente, id_plan, fecha_inicio, fecha_fin, estado) VALUES (%s,%s,%s,%s,'pendiente')", (id_cliente, datos.id_plan, fecha_inicio, fecha_fin))
        id_membresia = cur.lastrowid

        db.commit()
        token = crear_token(id_usuario, "cliente")
        cur.close()
        return {"access_token": token, "id_membresia": id_membresia, "estado_membresia": "pendiente", "fecha_fin": str(fecha_fin)}
    except HTTPException:
        db.rollback(); raise
    except Exception as e:
        db.rollback(); raise HTTPException(500, f"Error: {e}")

# --- CATÁLOGOS ---
@app.get("/api/planes")
def listar_planes(db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM planes WHERE activo=1 ORDER BY orden_visualizacion")
    planes = cur.fetchall()
    for p in planes:
        p["precio"] = float(p["precio"])
        cur.execute("SELECT b.id_beneficio, b.nombre, b.descripcion AS detalle FROM plan_beneficios pb JOIN beneficios b ON b.id_beneficio = pb.id_beneficio WHERE pb.id_plan=%s AND pb.incluido=1", (p["id_plan"],))
        p["beneficios"] = cur.fetchall()
    cur.close(); return planes

@app.get("/api/objetivos")
def listar_objetivos(db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM objetivos ORDER BY id_objetivo")
    r = cur.fetchall(); cur.close(); return r

@app.get("/api/ejercicios")
def listar_ejercicios(db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_ejercicio, nombre, grupo_muscular FROM ejercicios WHERE activo = 1")
    r = cur.fetchall(); cur.close(); return r

# --- PAGOS ---
@app.post("/api/pagos/simulado")
def pago_simulado(datos: PagoSimuladoIn, u: dict = Depends(usuario_actual), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT m.id_membresia, m.estado, p.precio FROM membresias m JOIN clientes c ON c.id_cliente = m.id_cliente JOIN planes p ON p.id_plan = m.id_plan WHERE m.id_membresia=%s AND c.id_usuario=%s", (datos.id_membresia, u["id_usuario"]))
    m = cur.fetchone()
    if not m: raise HTTPException(404, "Membresía no encontrada")
    if m["estado"] == "activa": return {"pago_aprobado": True, "acceso_dashboard": True, "id_membresia": m["id_membresia"], "mensaje": "Ya estaba activa"}

    referencia = f"SIM-{secrets.token_hex(10)}"
    cur.execute("INSERT INTO pagos (id_membresia, monto, metodo, estado, referencia, fecha_pago, observacion) VALUES (%s,%s,'simulado','aprobado',%s,NOW(),'Pago simulado')", (m["id_membresia"], m["precio"], referencia))
    db.commit(); cur.close()
    return {"pago_aprobado": True, "acceso_dashboard": True, "id_membresia": m["id_membresia"], "referencia": referencia}

# --- CLIENTE: RUTINAS Y ASISTENCIAS ---
@app.get("/api/cliente/dashboard")
def dashboard_cliente(u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    id_c = cur.fetchone()["id_cliente"]

    # 1. Rutina activa (asignada)
    cur.execute("""
        SELECT r.nombre, r.nivel, r.id_rutina,
               (SELECT COUNT(*) FROM rutina_ejercicios WHERE id_rutina = r.id_rutina) as total_ejercicios
        FROM asignaciones_rutinas ar
        JOIN rutinas r ON r.id_rutina = ar.id_rutina
        WHERE ar.id_cliente = %s AND ar.estado = 'activa'
        LIMIT 1
    """, (id_c,))
    rutina_hoy = cur.fetchone()

    # 2. Días activos (asistencias totales)
    cur.execute("SELECT COUNT(*) as total FROM asistencias WHERE id_cliente=%s", (id_c,))
    asistencias = cur.fetchone()["total"]

    # 3. Rutinas completadas
    cur.execute("SELECT COUNT(*) as total FROM rutinas_completadas WHERE id_cliente=%s", (id_c,))
    rutinas_completadas = cur.fetchone()["total"]

    cur.close()
    return {
        "rutina_hoy": rutina_hoy,
        "dias_activos": asistencias,
        "rutinas_completadas": rutinas_completadas
    }

@app.post("/api/completar-rutina", status_code=201)
def completar_rutina(datos: RutinaCompletadaIn, u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    id_c = cur.fetchone()[0]
    cur.execute("INSERT INTO rutinas_completadas (id_cliente, nombre_rutina) VALUES (%s, %s)", (id_c, datos.nombre_rutina))
    db.commit()
    cur.close()
    return {"mensaje": "¡Rutina completada!"}

@app.get("/api/mis-rutinas-completadas")
def mis_rutinas_completadas(u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    id_c = cur.fetchone()["id_cliente"]
    cur.execute("SELECT id_completada, nombre_rutina, fecha_completada FROM rutinas_completadas WHERE id_cliente=%s ORDER BY fecha_completada DESC", (id_c,))
    r = cur.fetchall()
    cur.close()
    return r

@app.get("/api/mis-asistencias")
def mis_asistencias(u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    id_c = cur.fetchone()["id_cliente"]
    cur.execute("SELECT id_asistencia, fecha_hora_entrada FROM asistencias WHERE id_cliente=%s ORDER BY fecha_hora_entrada DESC LIMIT 30", (id_c,))
    r = cur.fetchall()
    cur.close()
    return r

@app.post("/api/registrar-mi-asistencia", status_code=201)
def registrar_mi_asistencia(u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    id_c = cur.fetchone()["id_cliente"]
    
    cur.execute("SELECT id_asistencia FROM asistencias WHERE id_cliente=%s AND DATE(fecha_hora_entrada)=CURDATE()", (id_c,))
    if cur.fetchone():
        raise HTTPException(400, "Ya registraste tu asistencia hoy.")
    
    cur.execute("INSERT INTO asistencias (id_cliente) VALUES (%s)", (id_c,))
    db.commit()
    cur.close()
    return {"mensaje": "¡Asistencia registrada! Buen entrenamiento."}

@app.get("/api/mi-entrenador")
def obtener_mi_entrenador(u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    row = cur.fetchone()
    if not row:
        cur.close()
        raise HTTPException(404, "Cliente no encontrado")
    
    id_cliente = row["id_cliente"]
    cur.execute("""
        SELECT u.nombres, u.apellidos, u.correo, u.telefono
        FROM entrenador_clientes ec
        JOIN usuarios u ON u.id_usuario = ec.id_entrenador
        WHERE ec.id_cliente = %s AND ec.estado = 'activa'
        LIMIT 1
    """, (id_cliente,))
    entrenador = cur.fetchone()
    cur.close()

    if not entrenador:
        return {"asignado": False, "mensaje": "No tienes un entrenador asignado aún."}
    
    return {"asignado": True, **entrenador}

# --- ENTRENADOR ---
@app.get("/api/entrenador/mis-clientes")
def mis_clientes(u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT c.id_cliente, u.nombres, u.apellidos, u.correo, ec.fecha_asignacion, ec.estado FROM entrenador_clientes ec JOIN clientes c ON c.id_cliente = ec.id_cliente JOIN usuarios u ON u.id_usuario = c.id_usuario WHERE ec.id_entrenador=%s AND ec.estado='activa'", (u["id_usuario"],))
    r = cur.fetchall(); cur.close(); return r

class CrearRutinaIn(BaseModel):
    nombre: str
    descripcion: str
    nivel: str = "principiante"
    ejercicios: List[dict] = []  # Cada dict: {"id_ejercicio": int, "series": int, "repeticiones": str}

@app.post("/api/entrenador/crear-rutina", status_code=201)
def crear_rutina(datos: CrearRutinaIn, u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    if not datos.nombre or not datos.ejercicios:
        raise HTTPException(400, "Faltan datos de la rutina")
    cur = db.cursor()
    try:
        cur.execute(
            "INSERT INTO rutinas (id_entrenador, nombre, descripcion, nivel, activa) VALUES (%s, %s, %s, %s, 1)",
            (u["id_usuario"], datos.nombre, datos.descripcion, datos.nivel)
        )
        id_rutina = cur.lastrowid

        for orden, ej in enumerate(datos.ejercicios, start=1):
            cur.execute("""
                INSERT INTO rutina_ejercicios (id_rutina, id_ejercicio, orden, series, repeticiones)
                VALUES (%s, %s, %s, %s, %s)
            """, (id_rutina, ej.get("id_ejercicio"), orden, ej.get("series", 3), ej.get("repeticiones", "10-12")))
        
        db.commit()
        cur.close()
        return {"mensaje": "Rutina creada", "id_rutina": id_rutina}
    except Exception as e:
        db.rollback()
        cur.close()
        raise HTTPException(500, f"Error: {e}")
@app.get("/api/entrenador/rutinas")
def listar_rutinas_entrenador(u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_rutina, nombre, descripcion, nivel FROM rutinas WHERE id_entrenador=%s", (u["id_usuario"],))
    r = cur.fetchall()
    cur.close()
    return r

@app.post("/api/entrenador/asignar-rutina", status_code=201)
def asignar_rutina(datos: AsignarRutinaIn, u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    cur = db.cursor()
    try:
        cur.execute("UPDATE asignaciones_rutinas SET estado='completada' WHERE id_cliente=%s AND estado='activa'", (datos.id_cliente,))
        cur.execute("INSERT INTO asignaciones_rutinas (id_rutina, id_cliente, id_entrenador, fecha_inicio, estado) VALUES (%s, %s, %s, CURDATE(), 'activa')", (datos.id_rutina, datos.id_cliente, u["id_usuario"]))
        db.commit()
        return {"mensaje": "Rutina asignada correctamente"}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Error: {e}")
    finally:
        cur.close()

# --- ADMIN ---
@app.get("/api/admin/indicadores")
def indicadores(u=Depends(requiere_rol("administrador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT COUNT(*) AS n FROM clientes"); clientes = cur.fetchone()["n"]
    cur.execute("SELECT COUNT(*) AS n FROM membresias WHERE estado='activa' AND fecha_fin>=CURDATE()"); activos = cur.fetchone()["n"]
    cur.execute("SELECT COUNT(*) AS n FROM membresias WHERE estado='vencida' OR fecha_fin<CURDATE()"); vencidas = cur.fetchone()["n"]
    cur.execute("SELECT COUNT(*) AS n FROM asistencias WHERE DATE(fecha_hora_entrada)=CURDATE()"); hoy = cur.fetchone()["n"]
    cur.close()
    return {"clientes_totales": clientes, "clientes_activos": activos, "membresias_vencidas": vencidas, "asistencia_hoy": hoy}

@app.get("/api/admin/clientes")
def listar_clientes_admin(u=Depends(requiere_rol("administrador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT c.id_cliente, u.nombres, u.apellidos, u.correo, u.telefono, u.estado, c.nivel_experiencia FROM clientes c JOIN usuarios u ON u.id_usuario = c.id_usuario")
    r = cur.fetchall(); cur.close(); return r

@app.get("/api/admin/clientes-elegibles")
def listar_clientes_elegibles(u=Depends(requiere_rol("administrador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT c.id_cliente, u.nombres, u.apellidos, u.correo, u.telefono, u.estado, c.nivel_experiencia
        FROM clientes c
        JOIN usuarios u ON u.id_usuario = c.id_usuario
        JOIN membresias m ON m.id_cliente = c.id_cliente
        JOIN plan_beneficios pb ON pb.id_plan = m.id_plan
        JOIN beneficios b ON b.id_beneficio = pb.id_beneficio
        WHERE m.estado = 'activa' AND b.codigo = 'ENTRENADOR_ASIGNADO'
    """)
    r = cur.fetchall(); cur.close(); return r

@app.get("/api/admin/entrenadores")
def listar_entrenadores_admin(u=Depends(requiere_rol("administrador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT u.id_usuario, u.nombres, u.apellidos, u.correo, u.telefono, u.estado FROM usuarios u JOIN roles r ON r.id_rol = u.id_rol WHERE r.nombre = 'entrenador'")
    r = cur.fetchall(); cur.close(); return r

@app.post("/api/admin/asignar-entrenador")
def asignar_entrenador(datos: dict, u=Depends(requiere_rol("administrador")), db=Depends(get_db)):
    id_entrenador = datos.get("id_entrenador")
    id_cliente = datos.get("id_cliente")
    if not id_entrenador or not id_cliente:
        raise HTTPException(400, "Faltan datos")
        
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("UPDATE entrenador_clientes SET estado='finalizada' WHERE id_cliente=%s AND estado='activa'", (id_cliente,))
        cur.execute("INSERT INTO entrenador_clientes (id_entrenador, id_cliente, fecha_asignacion, estado) VALUES (%s, %s, CURDATE(), 'activa')", (id_entrenador, id_cliente))
        db.commit()
        return {"mensaje": "Entrenador asignado correctamente"}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Error al asignar: {e}")
    finally:
        cur.close()
@app.get("/api/mis-rutinas")
def mis_rutinas(u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    row = cur.fetchone()
    if not row:
        cur.close()
        raise HTTPException(404, "Cliente no encontrado")
    id_c = row["id_cliente"]

    cur.execute("""
        SELECT ar.id_asignacion_rutina, ar.fecha_inicio, ar.estado, 
               r.id_rutina, r.nombre, r.descripcion, r.nivel, 0 as es_general
        FROM asignaciones_rutinas ar 
        JOIN rutinas r ON r.id_rutina = ar.id_rutina 
        WHERE ar.id_cliente=%s AND ar.estado='activa'
    """, (id_c,))
    personalizadas = cur.fetchall()

    for r in personalizadas:
        cur.execute("""
            SELECT e.id_ejercicio, e.nombre, e.grupo_muscular, 
                   re.series, re.repeticiones 
            FROM rutina_ejercicios re 
            JOIN ejercicios e ON e.id_ejercicio = re.id_ejercicio 
            WHERE re.id_rutina=%s ORDER BY re.orden
        """, (r["id_rutina"],))
        r["ejercicios"] = cur.fetchall()

    cur.close()
    return personalizadas
@app.post("/api/registrar-mi-asistencia", status_code=201)
def registrar_mi_asistencia(u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    row = cur.fetchone()
    if not row:
        cur.close()
        raise HTTPException(404, "Cliente no encontrado")
    id_c = row["id_cliente"]
    
    # Verificamos que no haya registrado hoy para no duplicar
    cur.execute("SELECT id_asistencia FROM asistencias WHERE id_cliente=%s AND DATE(fecha_hora_entrada)=CURDATE()", (id_c,))
    if cur.fetchone():
        cur.close()
        raise HTTPException(400, "Ya registraste tu asistencia hoy.")
    
    cur.execute("INSERT INTO asistencias (id_cliente) VALUES (%s)", (id_c,))
    db.commit()
    cur.close()
    return {"mensaje": "¡Asistencia registrada! Buen entrenamiento."}
@app.get("/api/cliente/dashboard")
def dashboard_cliente(u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    id_c = cur.fetchone()["id_cliente"]

    # 1. Rutina activa (asignada)
    cur.execute("""
        SELECT r.nombre, r.nivel, r.id_rutina,
               (SELECT COUNT(*) FROM rutina_ejercicios WHERE id_rutina = r.id_rutina) as total_ejercicios
        FROM asignaciones_rutinas ar
        JOIN rutinas r ON r.id_rutina = ar.id_rutina
        WHERE ar.id_cliente = %s AND ar.estado = 'activa'
        LIMIT 1
    """, (id_c,))
    rutina_hoy = cur.fetchone()

    # 2. Días activos (asistencias totales)
    cur.execute("SELECT COUNT(*) as total FROM asistencias WHERE id_cliente=%s", (id_c,))
    asistencias = cur.fetchone()["total"]

    # 3. Rutinas completadas (NUEVO)
    cur.execute("SELECT COUNT(*) as total FROM rutinas_completadas WHERE id_cliente=%s", (id_c,))
    rutinas_completadas = cur.fetchone()["total"]

    cur.close()
    return {
        "rutina_hoy": rutina_hoy,
        "dias_activos": asistencias,
        "rutinas_completadas": rutinas_completadas
    }
@app.get("/api/entrenador/estadisticas")
def estadisticas_entrenador(u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    id_entrenador = u["id_usuario"]

    # 1. Cantidad de clientes asignados
    cur.execute("SELECT COUNT(*) as total FROM entrenador_clientes WHERE id_entrenador=%s AND estado='activa'", (id_entrenador,))
    clientes = cur.fetchone()["total"]

    # 2. Cantidad de rutinas creadas
    cur.execute("SELECT COUNT(*) as total FROM rutinas WHERE id_entrenador=%s", (id_entrenador,))
    rutinas = cur.fetchone()["total"]

    # 3. Cantidad de asignaciones activas
    cur.execute("SELECT COUNT(*) as total FROM asignaciones_rutinas WHERE id_entrenador=%s AND estado='activa'", (id_entrenador,))
    asignaciones = cur.fetchone()["total"]

    cur.close()
    return {
        "clientes": clientes,
        "rutinas": rutinas,
        "asignaciones": asignaciones
    }
@app.get("/api/entrenador/cliente/{id_cliente}")
def detalle_cliente_entrenador(id_cliente: int, u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    # Verificar que el cliente esté asignado a este entrenador
    cur.execute("SELECT 1 FROM entrenador_clientes WHERE id_entrenador=%s AND id_cliente=%s AND estado='activa'", (u["id_usuario"], id_cliente))
    if not cur.fetchone():
        cur.close()
        raise HTTPException(403, "Este cliente no está asignado a ti")

    # Datos del cliente
    cur.execute("""
        SELECT u.nombres, u.apellidos, u.correo, u.telefono, c.nivel_experiencia
        FROM clientes c JOIN usuarios u ON u.id_usuario = c.id_usuario
        WHERE c.id_cliente = %s
    """, (id_cliente,))
    cliente = cur.fetchone()

    # Rutinas completadas
    cur.execute("SELECT COUNT(*) as total FROM rutinas_completadas WHERE id_cliente=%s", (id_cliente,))
    rutinas_completadas = cur.fetchone()["total"]

    # Asistencias
    cur.execute("SELECT COUNT(*) as total FROM asistencias WHERE id_cliente=%s", (id_cliente,))
    asistencias = cur.fetchone()["total"]

    # Historial de rutinas completadas (últimas 10)
    cur.execute("""
        SELECT nombre_rutina, fecha_completada 
        FROM rutinas_completadas 
        WHERE id_cliente=%s 
        ORDER BY fecha_completada DESC LIMIT 10
    """, (id_cliente,))
    historial = cur.fetchall()

    cur.close()
    return {
        "cliente": cliente,
        "rutinas_completadas": rutinas_completadas,
        "asistencias": asistencias,
        "historial": historial
    }
@app.delete("/api/entrenador/rutinas/{id_rutina}")
def eliminar_rutina(id_rutina: int, u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    try:
        # Verificar que la rutina existe
        cur.execute("SELECT id_rutina FROM rutinas WHERE id_rutina=%s", (id_rutina,))
        if not cur.fetchone():
            raise HTTPException(404, "Rutina no encontrada")
        
        # Eliminar la rutina
        cur.execute("DELETE FROM rutinas WHERE id_rutina=%s", (id_rutina,))
        db.commit()
        cur.close()
        return {"mensaje": "Rutina eliminada"}
    except HTTPException:
        db.rollback(); raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Error: {e}")
    finally:
        cur.close()
class CrearEntrenadorIn(BaseModel):
    nombres: str
    apellidos: str
    correo: EmailStr
    telefono: str
    contrasena: str
    fecha_nacimiento: str
    tipo_documento: str
    numero_documento: str

@app.post("/api/admin/crear-entrenador", status_code=201)
def crear_entrenador(datos: CrearEntrenadorIn, u=Depends(requiere_rol("administrador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id_usuario FROM usuarios WHERE correo=%s OR numero_documento=%s", (datos.correo.lower(), datos.numero_documento))
        if cur.fetchone(): raise HTTPException(409, "Correo o documento ya registrado")

        cur.execute("""
            INSERT INTO usuarios (id_rol, nombres, apellidos, tipo_documento, numero_documento,
                                  correo, telefono, fecha_nacimiento, contrasena_hash, estado)
            VALUES (3, %s,%s,%s,%s,%s,%s,%s,%s,'activo')
        """, (datos.nombres, datos.apellidos, datos.tipo_documento, datos.numero_documento,
              datos.correo.lower(), datos.telefono, datos.fecha_nacimiento, hashear(datos.contrasena)))
        db.commit()
        return {"mensaje": "Entrenador creado"}
    except HTTPException:
        db.rollback(); raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Error: {e}")
    finally:
        cur.close()
@app.get("/api/admin/asistencias")
def listar_asistencias_admin(u=Depends(requiere_rol("administrador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT a.id_asistencia, a.fecha_hora_entrada, u.nombres, u.apellidos
        FROM asistencias a
        JOIN clientes c ON c.id_cliente = a.id_cliente
        JOIN usuarios u ON u.id_usuario = c.id_usuario
        ORDER BY a.fecha_hora_entrada DESC LIMIT 50
    """)
    r = cur.fetchall()
    cur.close()
    return r
@app.get("/api/admin/reportes")
def reportes(u=Depends(requiere_rol("administrador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    
    # 1. Ingresos totales
    cur.execute("SELECT COALESCE(SUM(monto), 0) as total FROM pagos WHERE estado='aprobado'")
    ingresos = float(cur.fetchone()["total"])
    
    # 2. Membresías activas por plan
    cur.execute("""
        SELECT p.nombre, COUNT(m.id_membresia) as total
        FROM planes p
        LEFT JOIN membresias m ON m.id_plan = p.id_plan AND m.estado = 'activa' AND m.fecha_fin >= CURDATE()
        GROUP BY p.id_plan, p.nombre
    """)
    por_plan = cur.fetchall()
    
    # 3. Total de membresías
    cur.execute("SELECT COUNT(*) as total FROM membresias")
    total_membresias = cur.fetchone()["total"]
    
    # 4. Asistencias del mes
    cur.execute("SELECT COUNT(*) as total FROM asistencias WHERE MONTH(fecha_hora_entrada)=MONTH(CURDATE()) AND YEAR(fecha_hora_entrada)=YEAR(CURDATE())")
    asistencias_mes = cur.fetchone()["total"]
    
    # 5. Rutinas completadas del mes
    cur.execute("SELECT COUNT(*) as total FROM rutinas_completadas WHERE MONTH(fecha_completada)=MONTH(CURDATE()) AND YEAR(fecha_completada)=YEAR(CURDATE())")
    rutinas_mes = cur.fetchone()["total"]
    
    cur.close()
    return {
        "ingresos_totales": ingresos,
        "por_plan": por_plan,
        "total_membresias": total_membresias,
        "asistencias_mes": asistencias_mes,
        "rutinas_mes": rutinas_mes
    }
@app.get("/api/admin/membresias")
def listar_membresias_admin(u=Depends(requiere_rol("administrador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM vista_membresias ORDER BY fecha_fin DESC")
    r = cur.fetchall()
    cur.close()
    return r

# --- DISPONIBILIDAD DEL ENTRENADOR ---
@app.post("/api/entrenador/disponibilidad")
def crear_disponibilidad(datos: dict, u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    fecha = datos.get("fecha")
    hora_inicio = datos.get("hora_inicio")
    hora_fin = datos.get("hora_fin")
    if not fecha or not hora_inicio or not hora_fin:
        raise HTTPException(400, "Faltan datos")
    cur = db.cursor()
    try:
        cur.execute(
            "INSERT INTO disponibilidad_entrenador (id_entrenador, fecha, hora_inicio, hora_fin) VALUES (%s, %s, %s, %s)",
            (u["id_usuario"], fecha, hora_inicio, hora_fin)
        )
        db.commit()
        return {"mensaje": "Disponibilidad creada"}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Error: {e}")
    finally:
        cur.close()

@app.get("/api/entrenador/disponibilidad")
def listar_disponibilidad(u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("""
        SELECT d.id_disponibilidad, d.fecha, d.hora_inicio, d.hora_fin, d.estado,
               (SELECT COUNT(*) FROM citas c WHERE c.id_disponibilidad = d.id_disponibilidad AND c.estado != 'cancelada') as reservas,
               (SELECT CONCAT(uc.nombres, ' ', uc.apellidos)
                FROM citas c
                JOIN clientes cl ON cl.id_cliente = c.id_cliente
                JOIN usuarios uc ON uc.id_usuario = cl.id_usuario
                WHERE c.id_disponibilidad = d.id_disponibilidad AND c.estado != 'cancelada'
                LIMIT 1) as cliente_reserva
        FROM disponibilidad_entrenador d
        WHERE d.id_entrenador = %s
        ORDER BY d.fecha, d.hora_inicio
    """, (u["id_usuario"],))
    r = cur.fetchall()
    cur.close()
    for item in r:
        if hasattr(item["hora_inicio"], "seconds"):
            h, m = divmod(item["hora_inicio"].seconds // 60, 60)
            item["hora_inicio"] = f"{h:02d}:{m:02d}"
        if hasattr(item["hora_fin"], "seconds"):
            h, m = divmod(item["hora_fin"].seconds // 60, 60)
            item["hora_fin"] = f"{h:02d}:{m:02d}"
        if hasattr(item["fecha"], "isoformat"):
            item["fecha"] = item["fecha"].isoformat()
    return r

@app.delete("/api/entrenador/disponibilidad/{id}")
def eliminar_disponibilidad(id: int, u=Depends(requiere_rol("entrenador")), db=Depends(get_db)):
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM disponibilidad_entrenador WHERE id_disponibilidad=%s AND id_entrenador=%s", (id, u["id_usuario"]))
        db.commit()
        return {"mensaje": "Disponibilidad eliminada"}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Error: {e}")
    finally:
        cur.close()

# --- DISPONIBILIDAD PARA EL CLIENTE (con nombre del entrenador) ---
@app.get("/api/cliente/disponibilidad-entrenador")
def disponibilidad_para_cliente(u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
    row = cur.fetchone()
    if not row:
        cur.close()
        raise HTTPException(404, "Cliente no encontrado")
    id_cliente = row["id_cliente"]

    cur.execute("""
        SELECT ec.id_entrenador, CONCAT(ue.nombres, ' ', ue.apellidos) as nombre_entrenador
        FROM entrenador_clientes ec
        JOIN usuarios ue ON ue.id_usuario = ec.id_entrenador
        WHERE ec.id_cliente = %s AND ec.estado = 'activa' LIMIT 1
    """, (id_cliente,))
    ent = cur.fetchone()
    if not ent:
        cur.close()
        return {"entrenador": None, "horarios": []}
    id_entrenador = ent["id_entrenador"]
    nombre_entrenador = ent["nombre_entrenador"]

    cur.execute("""
        SELECT d.id_disponibilidad, d.fecha, d.hora_inicio, d.hora_fin,
               (SELECT COUNT(*) FROM citas c WHERE c.id_disponibilidad = d.id_disponibilidad AND c.estado != 'cancelada') as reservas
        FROM disponibilidad_entrenador d
        WHERE d.id_entrenador = %s AND d.fecha >= CURDATE()
        ORDER BY d.fecha, d.hora_inicio
    """, (id_entrenador,))
    r = cur.fetchall()
    cur.close()
    for item in r:
        if hasattr(item["hora_inicio"], "seconds"):
            h, m = divmod(item["hora_inicio"].seconds // 60, 60)
            item["hora_inicio"] = f"{h:02d}:{m:02d}"
        if hasattr(item["hora_fin"], "seconds"):
            h, m = divmod(item["hora_fin"].seconds // 60, 60)
            item["hora_fin"] = f"{h:02d}:{m:02d}"
        if hasattr(item["fecha"], "isoformat"):
            item["fecha"] = item["fecha"].isoformat()
    
    return {"entrenador": nombre_entrenador, "horarios": r}

@app.post("/api/cliente/reservar-cita")
def reservar_cita(datos: dict, u=Depends(requiere_rol("cliente")), db=Depends(get_db)):
    id_disponibilidad = datos.get("id_disponibilidad")
    if not id_disponibilidad:
        raise HTTPException(400, "Falta la disponibilidad")
    
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id_cliente FROM clientes WHERE id_usuario=%s", (u["id_usuario"],))
        id_cliente = cur.fetchone()["id_cliente"]
        
        cur.execute("SELECT estado FROM disponibilidad_entrenador WHERE id_disponibilidad=%s", (id_disponibilidad,))
        disp = cur.fetchone()
        if not disp or disp["estado"] != "disponible":
            raise HTTPException(400, "Horario no disponible")
        
        cur.execute("SELECT id_cita FROM citas WHERE id_disponibilidad=%s AND estado != 'cancelada'", (id_disponibilidad,))
        if cur.fetchone():
            raise HTTPException(400, "Este horario ya fue reservado")
        
        cur.execute("""
            INSERT INTO citas (id_disponibilidad, id_cliente, estado)
            VALUES (%s, %s, 'pendiente')
        """, (id_disponibilidad, id_cliente))
        db.commit()
        return {"mensaje": "Cita reservada correctamente"}
    except HTTPException:
        db.rollback(); raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Error: {e}")
    finally:
        cur.close()
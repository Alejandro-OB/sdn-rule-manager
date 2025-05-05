---
Proyecto SDN con Ryu, Flask y SQLite
---
Este proyecto permite gestionar reglas de red de forma dinámica en switches SDN utilizando **Ryu**, **Flask** y **SQLite**.
---
Características
-  Controlador SDN (Ryu): Administra switches y reglas de tráfico dinámicamente.
-  API REST (Flask): Consulta, agrega, modifica y elimina reglas en una base de datos SQLite.
-  Persistencia (SQLite): Almacena reglas y logs de eventos en la red.
-  Interfaz Web (HTML): Panel básico para gestión de reglas.

---

## Estructura del Proyecto

```
mi_proyecto/
│── app/
│   ├── controllers/
│   │   ├── controller_v3.py
│   │   ├── server.py
│   ├── models/
│   │   ├── database.py
│   │   ├── migrar_a_sqlite.py
│   ├── static/
│   ├── templates/
│   │   ├── index.html
│   ├── config/
│   │   ├── reglas.json
│── docs/
│   ├── Architecture.png
│   ├── Implementation_Diagram.png
│   ├── Secuence_Diagram.png
│── tests/
│── .gitignore
│── requirements.txt
│── README.md
│── main.py
```

---

## Instalación

### Instalar dependencias

```bash
pip install -r requirements.txt
```

### Inicializar base de datos

```bash
python app/models/database.py
```

### Migrar datos desde JSON

```bash
python app/models/migrar_a_sqlite.py
```

### Ejecutar el servidor Flask

```bash
python app/controllers/server.py
```

API disponible en: `http://localhost:5000`

### Ejecutar controlador Ryu

```bash
ryu-manager app/controllers/controller_v3.py
```

---

## Endpoints API (Resumen)

### Obtener todas las reglas

```http
GET /reglas
```

### Agregar una nueva regla

```http
POST /reglas/{dpid}
```

**Ejemplo de cuerpo:**

```json
{
  "rule_id": 1002,
  "priority": 10,
  "eth_type": 2048,
  "ipv4_src": "192.168.1.3",
  "ipv4_dst": "192.168.1.4",
  "actions": ["OUTPUT:3"]
}
```

---

## Requisitos

- Python 3.8+
- Ryu SDN Controller
- Flask
- SQLite

---

## Mejoras Futuras

- 🔐 Autenticación en la API.
- 🧪 Pruebas unitarias.
- 💻 Interfaz web más avanzada.

---

_Desarrollado por **[Alejandro Ortega y Esteban Martinez]**_

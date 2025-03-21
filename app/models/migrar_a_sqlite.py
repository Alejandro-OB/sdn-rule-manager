import sqlite3

def inicializar_db():
    """Crea la base de datos y las tablas necesarias si no existen."""
    conn = sqlite3.connect("/home/ryu/Documents/ryu/proyectos/app_sqlite/reglas.db")
    cursor = conn.cursor()

    # 📌 Crear tabla `reglas` si no existe con los tipos de datos correctos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reglas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dpid INTEGER NOT NULL,
            rule_id INTEGER UNIQUE NOT NULL CHECK(rule_id > 0),
            priority INTEGER DEFAULT 1 CHECK(priority > 0),
            eth_type INTEGER NOT NULL CHECK(eth_type > 0),
            ip_proto INTEGER CHECK(ip_proto IS NULL OR ip_proto >= 0),
            ipv4_src TEXT NULL,
            ipv4_dst TEXT NULL,
            tcp_src INTEGER CHECK(tcp_src IS NULL OR tcp_src > 0),
            tcp_dst INTEGER CHECK(tcp_dst IS NULL OR tcp_dst > 0),
            in_port INTEGER CHECK(in_port IS NULL OR in_port > 0),
            actions TEXT NOT NULL CHECK(actions <> '')
        )
    """)

    # 📌 Crear tabla `logs` si no existe con los tipos de datos correctos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            dpid INTEGER,
            rule_id INTEGER CHECK(rule_id > 0),
            action TEXT CHECK(action IN ('INSTALADA', 'MODIFICADA', 'ELIMINADA')),
            priority INTEGER CHECK(priority > 0),
            eth_type INTEGER CHECK(eth_type > 0),
            ip_proto INTEGER CHECK(ip_proto IS NULL OR ip_proto >= 0),
            ipv4_src TEXT NULL,
            ipv4_dst TEXT NULL,
            tcp_src INTEGER CHECK(tcp_src IS NULL OR tcp_src > 0),
            tcp_dst INTEGER CHECK(tcp_dst IS NULL OR tcp_dst > 0),
            in_port INTEGER CHECK(in_port IS NULL OR in_port > 0),
            actions TEXT CHECK(actions <> '')
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Base de datos y tablas creadas correctamente.")

# 📌 Ejecutar la función solo si el script se ejecuta directamente
if __name__ == "__main__":
    inicializar_db()

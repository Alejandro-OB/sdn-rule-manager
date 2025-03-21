from flask import Flask, request, jsonify, render_template, g
import datetime
import os
import sqlite3
import json
from flask_cors import CORS
from contextlib import closing

# Initialize Flask application with static and template folders
app = Flask(__name__, static_folder=".", template_folder=".")
CORS(app)

# Define the path to the SQLite database
DATABASE = "/home/ryu/Documents/ryu/proyectos/app_sqlite/reglas.db"

# Function to establish a connection to the SQLite database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # Enable access to rows as dictionaries
    return g.db

# Close the database connection after each request
@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    # Render the main HTML page (index.html)
    return render_template('index.html')

@app.route('/reglas', methods=['GET'])
def obtener_reglas():
    """Retrieve all rules stored in the SQLite database."""
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Get all rules from the database
        cursor.execute("SELECT * FROM reglas")
        reglas = cursor.fetchall()

        if not reglas:
            return jsonify({"message": "No rules registered."}), 200

        # Convert results to JSON format
        reglas_lista = []
        for regla in reglas:
            reglas_lista.append({
                "dpid": regla["dpid"],
                "rule_id": regla["rule_id"],
                "priority": regla["priority"],
                "eth_type": regla["eth_type"],
                "ip_proto": regla["ip_proto"],
                "ipv4_src": regla["ipv4_src"],
                "ipv4_dst": regla["ipv4_dst"],
                "tcp_src": regla["tcp_src"],
                "tcp_dst": regla["tcp_dst"],
                "in_port": regla["in_port"],
                "actions": json.loads(regla["actions"]) if regla["actions"] else []
            })

        return jsonify({"switches": reglas_lista})

    except Exception as e:
        return jsonify({"error": f"Error fetching rules: {str(e)}"}), 500

@app.route('/reglas/buscar/<int:rule_id>', methods=['GET'])
def obtener_regla(rule_id):
    """Retrieve a specific rule by its Rule ID from the SQLite database."""
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Search for the rule by rule_id
        cursor.execute("SELECT * FROM reglas WHERE rule_id = ?", (rule_id,))
        regla = cursor.fetchone()

        if not regla:
            return jsonify({'error': 'Rule not found'}), 404

        return jsonify({
            "dpid": regla["dpid"],
            "rule_id": regla["rule_id"],
            "priority": regla["priority"],
            "eth_type": regla["eth_type"],
            "ip_proto": regla["ip_proto"],
            "ipv4_src": regla["ipv4_src"],
            "ipv4_dst": regla["ipv4_dst"],
            "tcp_src": regla["tcp_src"],
            "tcp_dst": regla["tcp_dst"],
            "in_port": regla["in_port"],
            "actions": json.loads(regla["actions"]) if regla["actions"] else []
        })

    except Exception as e:
        return jsonify({'error': f'Error fetching rule: {str(e)}'}), 500

@app.route('/reglas/max_rule_id', methods=['GET'])
def obtener_max_rule_id():
    """Retrieve the next available rule_id (maximum + 1) from the SQLite database."""
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT MAX(rule_id) FROM reglas")
        max_rule_id = cursor.fetchone()[0]

        next_rule_id = (max_rule_id + 1) if max_rule_id is not None else 1
        return jsonify({"next_rule_id": next_rule_id})

    except Exception as e:
        return jsonify({'error': f'Error on server: {str(e)}'}), 500

@app.route("/reglas/<int:dpid>", methods=["POST"])
def agregar_regla(dpid):
    """Add a new rule to the SQLite database."""
    try:
        data = request.json
        if not all(k in data for k in ["rule_id", "eth_type", "priority", "actions"]):
            return jsonify({"error": "Missing required fields."}), 400

        try:
            json.dumps(data["actions"])
        except ValueError:
            return jsonify({"error": "The 'actions' field must be valid JSON"}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reglas WHERE rule_id = ?", (data["rule_id"],))
        if cursor.fetchone():
            return jsonify({"error": "A rule with this ID already exists."}), 400

        cursor.execute("""
            INSERT INTO reglas (dpid, rule_id, priority, eth_type, ip_proto, ipv4_src, ipv4_dst, tcp_src, tcp_dst, in_port, actions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            dpid,
            int(data["rule_id"]),
            int(data["priority"]),
            int(data["eth_type"]),
            int(data.get("ip_proto", 0)),
            data.get("ipv4_src"),
            data.get("ipv4_dst"),
            int(data.get("tcp_src", 0)) if data.get("tcp_src") else None,
            int(data.get("tcp_dst", 0)) if data.get("tcp_dst") else None,
            int(data.get("in_port", 0)) if data.get("in_port") else None,
            json.dumps(data["actions"])
        ))

        conn.commit()
        return jsonify({"message": "Rule added successfully", "rule_id": data["rule_id"]})

    except Exception as e:
        return jsonify({"error": f"Error adding rule: {str(e)}"}), 500

@app.route("/reglas/modificar/<int:rule_id>", methods=["PUT"])
def modificar_regla(rule_id):
    """Update an existing rule in the SQLite database."""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided for modification"}), 400

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM reglas WHERE rule_id = ?", (rule_id,))
        regla = cursor.fetchone()

        if not regla:
            return jsonify({"error": "Rule not found"}), 404

        valid_columns = [
            "dpid", "priority", "eth_type", "ip_proto", "ipv4_src", "ipv4_dst",
            "tcp_src", "tcp_dst", "in_port", "actions"
        ]

        fields_to_update = []
        values = []
        for key, value in data.items():
            if key in valid_columns:
                if key == "actions":
                    try:
                        json.dumps(value)
                        value = json.dumps(value)
                    except ValueError:
                        return jsonify({"error": "The 'actions' field must be valid JSON"}), 400
                fields_to_update.append(f"{key} = ?")
                values.append(value)

        if not fields_to_update:
            return jsonify({"error": "No valid fields provided for update"}), 400

        values.append(rule_id)
        sql_update = f"UPDATE reglas SET {', '.join(fields_to_update)} WHERE rule_id = ?"
        cursor.execute(sql_update, values)
        conn.commit()

        return jsonify({"message": "Rule modified successfully", "rule_id": rule_id})

    except Exception as e:
        return jsonify({"error": f"Error modifying rule: {str(e)}"}), 500

@app.route('/logs', methods=['GET'])
def obtener_logs():
    """Retrieve all change logs from the SQLite database."""
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")
        logs = cursor.fetchall()

        if not logs:
            return jsonify({"message": "No log records."}), 200

        logs_lista = []
        for log in logs:
            logs_lista.append({
                "id": log["id"],
                "timestamp": log["timestamp"],
                "dpid": log["dpid"],
                "rule_id": log["rule_id"],
                "action": log["action"],
                "priority": log["priority"],
                "eth_type": log["eth_type"],
                "ip_proto": log["ip_proto"],
                "ipv4_src": log["ipv4_src"],
                "ipv4_dst": log["ipv4_dst"],
                "tcp_src": log["tcp_src"],
                "tcp_dst": log["tcp_dst"],
                "in_port": log["in_port"],
                "actions": json.loads(log["actions"]) if log["actions"] else []
            })

        return jsonify(logs_lista)

    except Exception as e:
        return jsonify({"error": f"Error fetching logs: {str(e)}"}), 500

@app.route("/reglas/eliminar/<int:rule_id>", methods=["DELETE"])
def eliminar_regla(rule_id):
    """Delete a specific rule from the SQLite database."""
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Verify if the rule exists
        cursor.execute("SELECT * FROM reglas WHERE rule_id = ?", (rule_id,))
        regla = cursor.fetchone()

        if not regla:
            return jsonify({"error": "Rule not found"}), 404

        dpid = regla["dpid"]

        # Delete the rule
        cursor.execute("DELETE FROM reglas WHERE rule_id = ?", (rule_id,))
        conn.commit()

        # Verify if the switch has more associated rules
        cursor.execute("SELECT COUNT(*) FROM reglas WHERE dpid = ?", (dpid,))
        count = cursor.fetchone()[0]

        # If no more rules exist for that switch, delete it from the switches table
        if count == 0:
            cursor.execute("SELECT * FROM switches WHERE dpid = ?", (dpid,))
            switch = cursor.fetchone()
            if switch:
                cursor.execute("DELETE FROM switches WHERE dpid = ?", (dpid,))
                conn.commit()

        return jsonify({"message": "Rule deleted successfully", "rule_id": rule_id})

    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"Error deleting rule: {str(e)}"}), 500

if __name__ == '__main__':
    # Start the Flask application in debug mode, accessible on all network interfaces
    app.run(debug=True, host="0.0.0.0", port=5000)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import sqlite3
import json
import time

class Config:
    # Path to the SQLite database containing the rules
    db_path = "/home/juanes/enfa/reglas.db"

class DynamicFlowSwitch(app_manager.RyuApp):
    # Supported OpenFlow versions
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicFlowSwitch, self).__init__(*args, **kwargs)
        # Dictionary to store datapaths (switches)
        self.datapaths = {}
        # Dictionary to track installed flows
        self.installed_flows = {}
        # Dictionary to cache rules from the database
        self.db_rules = {}
        # Flag to control the monitoring thread
        self.running = True
        # Path to the database
        self.db_path = Config.db_path
        self.logger.info("DynamicFlowSwitch initialized.")
        # Interval for monitoring database changes
        self.monitor_interval = kwargs.get('monitor_interval', 10)
        # Start the monitoring thread
        self.monitor_thread = hub.spawn(self.monitorizar_reglas)

    def obtener_conexion_bd(self):
        # Establish a connection to the SQLite database
        return sqlite3.connect(self.db_path)

    def guardar_log_en_sqlite(self, regla, action="INSTALADA"):
        """
        Save a log entry in the 'logs' table for rule changes.
        """
        try:
            conn = self.obtener_conexion_bd()
            cursor = conn.cursor()

            # Serialize actions to JSON format
            actions = regla.get("actions", [])
            actions_str = json.dumps(actions)

            # Ensure 'dpid' is not None or empty
            dpid = regla.get("dpid")
            if dpid is None:
                raise ValueError("The 'dpid' field cannot be None")

            # Insert the log entry into the 'logs' table
            self.logger.info(f"Inserting log for rule {regla.get('rule_id')} into the SQLite database...")
            cursor.execute("""
                INSERT INTO logs (
                    dpid, 
                    rule_id, 
                    action, 
                    priority, 
                    eth_type, 
                    ip_proto, 
                    ipv4_src, 
                    ipv4_dst, 
                    tcp_src, 
                    tcp_dst, 
                    in_port, 
                    actions
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                dpid,  
                regla.get("rule_id"),
                action,  
                regla.get("priority", 1),
                regla.get("eth_type"),
                regla.get("ip_proto"),
                regla.get("ipv4_src"),
                regla.get("ipv4_dst"),
                regla.get("tcp_src"),
                regla.get("tcp_dst"),
                regla.get("in_port"),
                actions_str
            ))
            conn.commit()
            self.logger.info(f"Log recorded for rule {regla.get('rule_id')}.")

        except sqlite3.Error as e:
            # Rollback in case of a database error
            conn.rollback()
            self.logger.error(f"Error saving log to SQLite database: {e}")
        except ValueError as ve:
            self.logger.error(f"Validation error: {ve}")
        finally:
            conn.close()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handle the switch connection event and install default and database rules.
        """
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default rule: send unknown packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, rule_id=0)

        self.logger.info(f"Switch {dpid} connected. Installing rules from the database...")
        reglas_db = self.obtener_reglas_desde_db().get(dpid, {})
        self.db_rules.setdefault(dpid, {}).update(reglas_db)
        if not reglas_db:
            self.logger.warning(f"No rules found for switch {dpid}.")
        else:
            self.logger.info(f"Rules for {dpid} loaded ({len(reglas_db)} rules).")
        self._install_db_rules(datapath, reglas_db)

    def add_flow(self, datapath, priority, match, actions, rule_id=0):
        """
        Add a flow to the switch.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=rule_id,  # Use the cookie field to identify the rule
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def _install_db_rules(self, datapath, reglas_nuevas):
        """
        Install rules from the database on the switch.
        """
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info(f"Installing rules on switch {dpid}.")
        if not reglas_nuevas:
            self.logger.warning(f"No rules defined for {dpid}. Setting NORMAL traffic.")
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.add_flow(datapath, 1, match, actions, rule_id=0)
            return
        for rule_id, rule in reglas_nuevas.items():
            priority = rule["priority"]
            match_dict = self._parse_match_data(rule["match_data"])
            if not match_dict:
                self.logger.warning(f"Rule {rule_id} has no valid match in {dpid}.")
                continue
            flow_match = parser.OFPMatch(**match_dict)
            actions_openflow = self._parse_actions(rule["actions"], parser, ofproto)
            self.add_flow(datapath, priority, flow_match, actions_openflow, rule_id=int(rule_id))
            self.installed_flows.setdefault(dpid, {})[rule_id] = (priority, match_dict, rule["actions"])
            self.logger.info(f"Rule {rule_id} installed on switch {dpid}.")
            # Log the action
            self.guardar_log_en_sqlite(rule, action="INSTALADA")

    def monitorizar_reglas(self):
        """
        Monitor the database for rule changes and apply them dynamically.
        """
        while self.running:
            try:
                nuevas_db = self.obtener_reglas_desde_db()
                cambios_detectados = self.comparar_reglas(self.db_rules, nuevas_db)
                if cambios_detectados:
                    for cambio in cambios_detectados:
                        dpid = cambio["dpid"]
                        rule_id = cambio["rule_id"]
                        campo_modificado = cambio["campo"]
                        valor_antiguo = cambio.get("valor_antiguo")
                        valor_nuevo = cambio.get("valor_nuevo")
                        self.logger.info(f"Change detected on switch {dpid} for rule {rule_id}: {campo_modificado}.")
                        self.aplicar_cambios(dpid, rule_id, campo_modificado, valor_antiguo, valor_nuevo)
                    # Update the local copy of the database
                    self.db_rules = nuevas_db
            except sqlite3.OperationalError as e:
                self.logger.warning(f"SQLite error: {e}.")
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}.")
            time.sleep(self.monitor_interval)

    def obtener_reglas_desde_db(self):
        """
        Load rules from the database and construct a dictionary
        with rules organized by dpid -> rule_id -> rule data.
        """
        try:
            conn = self.obtener_conexion_bd()
            cursor = conn.cursor()
            cursor.execute("BEGIN EXCLUSIVE TRANSACTION;")
            cursor.execute(
                "SELECT rule_id, dpid, priority, eth_type, ip_proto, ipv4_src, ipv4_dst, tcp_src, tcp_dst, in_port, actions FROM reglas"
            )
            reglas = cursor.fetchall()
            conn.commit()
            conn.close()

            reglas_dict = {}
            for regla in reglas:
                (rule_id, dpid, priority, eth_type, ip_proto,
                 ipv4_src, ipv4_dst, tcp_src, tcp_dst, in_port, actions) = regla

                # Construct the match dict
                match_dict = {
                    "eth_type": eth_type,
                    "ip_proto": ip_proto,
                    "ipv4_src": ipv4_src,
                    "ipv4_dst": ipv4_dst,
                    "tcp_src": tcp_src,
                    "tcp_dst": tcp_dst,
                    "in_port": in_port
                }
                # Remove keys that are None
                match_dict = {k: v for k, v in match_dict.items() if v is not None}

                # Parse 'actions' if it's JSON
                if isinstance(actions, str):
                    try:
                        actions_list = json.loads(actions)
                    except json.JSONDecodeError:
                        actions_list = []
                elif isinstance(actions, list):
                    actions_list = actions
                else:
                    actions_list = []

                # Save the rule both in match_data and top-level keys
                reglas_dict.setdefault(dpid, {})[rule_id] = {
                    "rule_id": rule_id,
                    "dpid": dpid,
                    "priority": priority,
                    # Also add these fields so they are not None in logs
                    "eth_type": eth_type,
                    "ip_proto": ip_proto,
                    "ipv4_src": ipv4_src,
                    "ipv4_dst": ipv4_dst,
                    "tcp_src": tcp_src,
                    "tcp_dst": tcp_dst,
                    "in_port": in_port,
                    "match_data": match_dict,
                    "actions": actions_list
                }
            return reglas_dict

        except sqlite3.OperationalError as e:
            self.logger.error(f"SQLite error: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
            return {}

    def comparar_reglas(self, reglas_antiguas, reglas_nuevas):
        """
        Compare old and new rules to detect changes.
        """
        cambios = []
        # Iterate through each switch (dpid)
        dpids = set(list(reglas_antiguas.keys()) + list(reglas_nuevas.keys()))
        for dpid in dpids:
            old_rules = reglas_antiguas.get(dpid, {})
            new_rules = reglas_nuevas.get(dpid, {})
            old_ids = set(old_rules.keys())
            new_ids = set(new_rules.keys())

            # Created rules
            for rule_id in new_ids - old_ids:
                cambios.append({
                    "dpid": dpid,
                    "rule_id": rule_id,
                    "campo": "Creada",
                    "valor_antiguo": None,
                    "valor_nuevo": new_rules[rule_id]
                })

            # Deleted rules
            for rule_id in old_ids - new_ids:
                cambios.append({
                    "dpid": dpid,
                    "rule_id": rule_id,
                    "campo": "Eliminada",
                    "valor_antiguo": old_rules[rule_id],
                    "valor_nuevo": None
                })

            # Existing rules: compare fields
            for rule_id in new_ids & old_ids:
                new_rule = new_rules[rule_id]
                old_rule = old_rules[rule_id]
                if new_rule.get("match_data", {}) != old_rule.get("match_data", {}):
                    cambios.append({
                        "dpid": dpid,
                        "rule_id": rule_id,
                        "campo": "match_data",
                        "valor_antiguo": old_rule.get("match_data"),
                        "valor_nuevo": new_rule.get("match_data")
                    })
                if new_rule.get("actions", []) != old_rule.get("actions", []):
                    cambios.append({
                        "dpid": dpid,
                        "rule_id": rule_id,
                        "campo": "actions",
                        "valor_antiguo": old_rule.get("actions"),
                        "valor_nuevo": new_rule.get("actions")
                    })
                if new_rule.get("priority") != old_rule.get("priority"):
                    cambios.append({
                        "dpid": dpid,
                        "rule_id": rule_id,
                        "campo": "priority",
                        "valor_antiguo": old_rule.get("priority"),
                        "valor_nuevo": new_rule.get("priority")
                    })
        return cambios

    def aplicar_cambios(self, dpid, rule_id, campo_modificado, valor_antiguo, valor_nuevo):
        """
        Apply changes to the switch based on detected rule modifications.
        """
        if campo_modificado in ['priority', 'match_data', 'actions']:
            self.actualizar_regla_switch(rule_id, campo_modificado, valor_nuevo, dpid)
        elif campo_modificado == "Eliminada":
            # For deletion, use the old information
            self.eliminar_regla_switch(rule_id, dpid, valor_antiguo["match_data"], valor_antiguo["priority"])
            if rule_id in self.installed_flows.get(dpid, {}):
                del self.installed_flows[dpid][rule_id]
        elif campo_modificado == "Creada":
            self.instalar_nueva_regla(rule_id, valor_nuevo, dpid)

    def actualizar_regla_switch(self, rule_id, campo, nuevo_valor, dpid):
        """
        Update a rule on the switch.
        """
        self.logger.info(f"Updating rule {rule_id} on switch {dpid}.")
        datapath = self.datapaths.get(dpid)
        if not datapath:
            self.logger.warning(f"Switch {dpid} not found.")
            return
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Get the updated rule from the database
        nuevas_reglas = self.obtener_reglas_desde_db()
        regla_modificada = nuevas_reglas.get(dpid, {}).get(rule_id)
        if not regla_modificada:
            self.logger.warning(f"Rule {rule_id} not found in DB for switch {dpid}.")
            return

        # Delete the previously installed rule (if it exists)
        installed_rule = self.installed_flows.get(dpid, {}).get(rule_id)
        if installed_rule:
            old_priority, old_match, old_actions = installed_rule
            self.eliminar_regla_switch(rule_id, dpid, old_match, old_priority)
            hub.sleep(1)

        # Install the rule with updated data
        new_priority = regla_modificada["priority"]
        new_match_data = regla_modificada["match_data"]
        new_actions = regla_modificada["actions"]
        match_dict = new_match_data if isinstance(new_match_data, dict) else json.loads(new_match_data)
        match = parser.OFPMatch(**match_dict)
        actions_openflow = self._parse_actions(new_actions, parser, ofproto)
        self.add_flow(datapath, new_priority, match, actions_openflow, rule_id=int(rule_id))

        self.installed_flows.setdefault(dpid, {})[rule_id] = (new_priority, match_dict, new_actions)
        self.logger.info(f"Rule {rule_id} updated on switch {dpid}.")

        # Log the action
        self.guardar_log_en_sqlite(regla_modificada, action="MODIFICADA")

    def eliminar_regla_switch(self, rule_id, dpid, match_data, priority):
        """
        Delete a rule from the switch.
        """
        try:
            datapath = self.datapaths.get(dpid)
            if not datapath:
                return False
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match_dict = match_data if isinstance(match_data, dict) else json.loads(match_data)
            match = parser.OFPMatch(**match_dict)
            mod_delete = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                match=match,
                priority=priority,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY
            )
            datapath.send_msg(mod_delete)

            # Resend the message a few times to confirm deletion
            for _ in range(3):
                hub.sleep(2)
                datapath.send_msg(mod_delete)

            self.logger.info(f"Rule {rule_id} deleted on switch {dpid}.")
            # Log the action
            self.guardar_log_en_sqlite({"dpid": dpid, "rule_id": rule_id}, action="ELIMINADA")
            return True
        except Exception as e:
            self.logger.error(f"Error deleting rule {rule_id} on switch {dpid}: {e}")
            return False

    def instalar_nueva_regla(self, rule_id, nuevo_valor, dpid):
        """
        Install a new rule on the switch.
        """
        self.logger.info(f"Installing new rule {rule_id} on switch {dpid}.")
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match_data = nuevo_valor.get("match_data")
        actions = nuevo_valor.get("actions")
        priority = nuevo_valor.get("priority")
        if not match_data or not actions or priority is None:
            return

        match_dict = match_data if isinstance(match_data, dict) else json.loads(match_data)
        match = parser.OFPMatch(**match_dict)
        actions_openflow = self._parse_actions(actions, parser, ofproto)
        self.add_flow(datapath, priority, match, actions_openflow, rule_id=int(rule_id))

        self.installed_flows.setdefault(dpid, {})[rule_id] = (priority, match_dict, actions)
        self.logger.info(f"New rule {rule_id} installed on switch {dpid}.")

        # Log the action
        self.guardar_log_en_sqlite(nuevo_valor, action="INSTALADA")

    def _parse_actions(self, actions_data, parser, ofproto):
        """
        Parse actions from the rule data.
        """
        actions = []
        if isinstance(actions_data, str):
            try:
                actions_list = json.loads(actions_data)
            except json.JSONDecodeError:
                return []
        elif isinstance(actions_data, list):
            actions_list = actions_data
        else:
            return []

        for act in actions_list:
            action_type = act.get("type", "").upper()
            if action_type == "OUTPUT":
                actions.append(parser.OFPActionOutput(int(act["port"])))
            elif action_type == "DROP":
                # DROP means not adding actions.
                continue
            elif action_type == "NORMAL":
                actions.append(parser.OFPActionOutput(ofproto.OFPP_NORMAL))
        return actions

    def _parse_match_data(self, match_data):
        """
        Parse match data from the rule data.
        """
        try:
            if isinstance(match_data, str):
                return json.loads(match_data)
            elif isinstance(match_data, dict):
                return match_data
            else:
                return {}
        except Exception as e:
            self.logger.error(f"Error parsing match_data: {e}")
            return {}

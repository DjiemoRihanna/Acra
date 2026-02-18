"""
Capture et analyse réseau avec Scapy pour ACRA SOC
Responsable de la découverte d'équipements et de la topologie réseau
"""
import eventlet
eventlet.monkey_patch()

import scapy.all as scapy
from datetime import datetime, timedelta
import time
import threading
import sys
import signal
import socket
import os
import json
import random

# Import des extensions et modèles
from src.extensions import db
from src.models import NetworkAsset, NetworkFlow, Alert
from src.core.event_bus import bus

class NetworkScannerService:
    def __init__(self, app, interface="eth0", ip_range="192.168.1.0/24"):
        self.app = app
        self.interface = interface
        self.ip_range = ip_range
        self.running = True
        self.mon_ip = self._get_mon_ip()
        print(f"[ACRA] 🖥️ Mon IP système: {self.mon_ip}")
        
        # Dictionnaires pour stocker les données en mémoire
        self.connections = {}
        self.device_ports = {}  # IP -> set(ports)
        
        # Simulation d'alertes pour les tests (à retirer en production)
        self.simulate_alerts = os.getenv('SIMULATE_ALERTS', 'False').lower() == 'true'
        
    def _get_mon_ip(self):
        """Détecte l'IP de la machine qui fait tourner ACRA"""
        try:
            # Connexion à un host externe pour obtenir l'IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            try:
                hostname = socket.gethostname()
                return socket.gethostbyname(hostname)
            except:
                return '192.168.1.100'

    def is_private_ip(self, ip):
        """Vérifie si une IP est privée (réseau local)"""
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.') or \
           ip.startswith('172.17.') or ip.startswith('172.18.') or ip.startswith('172.19.') or \
           ip.startswith('172.2') or ip.startswith('127.'):
            return True
        return False

    def discovery_loop(self):
        """Boucle de scan ARP pour détecter les appareils"""
        while self.running:
            try:
                print(f"[ACRA] 📡 Scan ARP sur {self.ip_range}...")
                ans, _ = scapy.srp(
                    scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.ip_range), 
                    timeout=2, 
                    verbose=False,
                    iface=self.interface
                )
                
                # IMPORTANT : Créer un nouveau contexte pour chaque itération
                with self.app.app_context():
                    found_ips = []
                    for _, rcv in ans:
                        ip = rcv.psrc
                        mac = rcv.hwsrc
                        
                        # Ignorer les IPs spéciales
                        if ip in ['0.0.0.0', '255.255.255.255'] or ip.startswith('224.'):
                            continue
                            
                        found_ips.append(ip)
                        
                        asset = NetworkAsset.query.filter_by(ip_address=ip).first()
                        if not asset:
                            # Nouvel appareil trouvé
                            device_type = self._guess_device_type(ip, mac)
                            manufacturer = self._get_manufacturer_from_mac(mac)
                            asset = NetworkAsset(
                                ip_address=ip, 
                                mac_address=mac, 
                                status='online',
                                last_seen=datetime.utcnow(),
                                asset_type='internal' if self.is_private_ip(ip) else 'external',
                                device_type=device_type,
                                hostname='Inconnu',
                                os_info=manufacturer,
                                total_bytes_sent=0,
                                total_bytes_received=0,
                                top_domains=[]
                            )
                            db.session.add(asset)
                            print(f"[ACRA] ➕ Nouvel appareil: {ip} ({mac}) - {device_type} - {manufacturer}")
                            
                            # Publier le nouvel appareil
                            bus.publish_scapy_device({
                                'ip': ip,
                                'mac': mac,
                                'device_type': device_type,
                                'os': manufacturer,
                                'manufacturer': manufacturer,
                                'total_bytes': 0,
                                'total_packets': 0,
                                'open_ports': [],
                                'behaviors': [],
                                'location': 'internal' if self.is_private_ip(ip) else 'external',
                                'last_seen': datetime.now().isoformat(),
                                'sites': []
                            })
                        else:
                            # Appareil connu
                            asset.status = 'online'
                            asset.last_seen = datetime.utcnow()
                            if asset.mac_address != mac:
                                asset.mac_address = mac
                    
                    # Marquer les appareils non vus comme offline après 2 minutes
                    all_assets = NetworkAsset.query.filter_by(status='online').all()
                    for asset in all_assets:
                        if asset.ip_address not in found_ips and asset.ip_address != self.mon_ip:
                            if (datetime.utcnow() - asset.last_seen).total_seconds() > 120:
                                asset.status = 'offline'
                                print(f"[ACRA] ⚫ Appareil hors ligne: {asset.ip_address}")

                    db.session.commit()
                    
                    # Publier la topologie
                    self.publish_topology()
                
            except Exception as e:
                print(f"[ACRA] ❌ Erreur Scan: {e}")
                try:
                    with self.app.app_context():
                        db.session.rollback()
                except:
                    pass
            
            time.sleep(30)

    def packet_callback(self, packet):
        """Analyse chaque paquet pour le trafic et les sites (DNS)"""
        try:
            if packet.haslayer(scapy.IP):
                ip_src = packet[scapy.IP].src
                ip_dst = packet[scapy.IP].dst
                size = len(packet)

                # Ignorer le broadcast et multicast
                if ip_src.startswith('224.') or ip_dst.startswith('224.') or \
                   ip_src in ['0.0.0.0', '255.255.255.255'] or ip_dst in ['0.0.0.0', '255.255.255.255']:
                    return
                
                # Créer un contexte pour chaque paquet
                with self.app.app_context():
                    # Mise à jour du trafic
                    asset = NetworkAsset.query.filter_by(ip_address=ip_src).first()
                    if asset:
                        asset.total_bytes_sent = (asset.total_bytes_sent or 0) + size
                        
                        # Enregistrer la connexion
                        if ip_src not in self.connections:
                            self.connections[ip_src] = []
                        if ip_dst not in self.connections[ip_src] and ip_dst != ip_src:
                            self.connections[ip_src].append(ip_dst)
                        
                        # Détection des ports
                        if packet.haslayer(scapy.TCP):
                            tcp = packet[scapy.TCP]
                            if ip_src not in self.device_ports:
                                self.device_ports[ip_src] = set()
                            self.device_ports[ip_src].add(tcp.sport)
                            self.device_ports[ip_src].add(tcp.dport)
                        
                        # Capture DNS
                        if packet.haslayer(scapy.DNSQR):
                            dns = packet[scapy.DNSQR]
                            domain = dns.qname.decode('utf-8', errors='ignore').rstrip('.')
                            
                            # Nettoyer le domaine
                            domain_parts = domain.split('.')
                            if len(domain_parts) > 2:
                                domain = '.'.join(domain_parts[-2:])
                            
                            current_sites = list(asset.top_domains or [])
                            if domain not in current_sites:
                                current_sites.append(domain)
                                asset.top_domains = current_sites[-20:]
                                print(f"[ACRA] 🌐 {ip_src} -> {domain}")
                        
                        db.session.commit()
                        
        except Exception as e:
            pass

    def _guess_device_type(self, ip, mac):
        """Devine le type d'appareil basé sur l'IP et MAC"""
        # Routeur probable
        if ip.endswith('.1') or ip.endswith('.254'):
            return 'router'
        
        # Serveur probable (ports communs)
        if ip in self.device_ports:
            ports = self.device_ports.get(ip, set())
            if 80 in ports or 443 in ports or 3306 in ports or 5432 in ports:
                return 'server'
        
        # Par défaut
        return 'computer'

    def _get_manufacturer_from_mac(self, mac):
        """Identifie le fabricant à partir du MAC"""
        mac_prefixes = {
            '00:14:BF': 'Cisco',
            '00:1C:10': 'Netgear',
            'CC:32:37': 'TP-Link',
            '00:1A:2B': 'Linksys',
            '00:1E:58': 'D-Link',
            '00:0C:41': '3Com',
            '08:00:27': 'Virtual',
            '00:50:7F': 'VMware',
            '00:25:90': 'Synology',
            '00:26:B9': 'QNAP',
            '00:11:32': 'HP',
            '00:1E:67': 'Dell',
            '00:1B:FC': 'Intel',
            '00:23:AE': 'Dell',
            '00:24:E8': 'HP',
            '00:1E:8F': 'HP',
            '00:1C:C4': 'Brother',
            '00:17:C8': 'Canon',
            '00:12:3F': 'Axis',
            '00:1C:27': 'Hikvision',
            'AC:CC:8C': 'Dahua',
            '10:AE:60': 'Sonos',
            '18:FE:34': 'Philips',
            'B8:27:EB': 'Raspberry',
            '00:04:13': 'Cisco VoIP',
            '00:0F:7C': 'Polycom',
            '00:12:CF': 'Cisco VoIP',
            '00:1E:52': 'Apple',
            '00:21:E9': 'Apple',
            '00:23:76': 'Samsung'
        }
        
        mac_upper = mac.upper()
        for prefix, manufacturer in mac_prefixes.items():
            if mac_upper.startswith(prefix):
                return manufacturer
        return 'Inconnu'

    def _check_for_alerts(self, asset):
        """Vérifie si l'appareil a des alertes (simulées pour l'instant)"""
        if not self.simulate_alerts:
            return None
        
        # Simulation aléatoire pour tester
        if random.random() < 0.05:  # 5% de chance
            severity = random.choice(['P1', 'P2'])
            return {
                'ip': asset.ip_address,
                'severity': severity,
                'count': random.randint(1, 3)
            }
        return None

    def publish_topology(self):
        """Publie les données de topologie pour le frontend"""
        try:
            nodes = []
            edges = []
            
            # IPs à ignorer (broadcast, multicast, loopback)
            ignore_ips = [
                '0.0.0.0', '255.255.255.255', '127.0.0.1',
                '224.0.0.1', '224.0.0.251', '239.255.255.250'
            ]
            
            # 1. Noeud ACRA (ton système)
            nodes.append({
                'id': self.mon_ip,
                'label': 'ACRA',
                'type': 'acra_system',
                'location': 'internal',
                'size': 100,
                'packets': 0,
                'os': 'ACRA SOC',
                'manufacturer': 'ACRA',
                'last_seen': datetime.now().isoformat(),
                'total_bytes': 0,
                'open_ports': [],
                'sites': [],
                'alert_count': 0,
                'alert_severity': None
            })
            
            # 2. Récupérer uniquement les appareils actifs
            with self.app.app_context():
                assets = NetworkAsset.query.filter_by(status='online').all()
                edge_ids = set()
                vrai_appareils = 0
                
                for asset in assets:
                    ip = asset.ip_address
                    
                    # FILTRES STRICTS : uniquement les vrais appareils
                    
                    # Ignorer les IPs spéciales
                    if ip in ignore_ips:
                        continue
                        
                    # Ignorer les IPv6
                    if ip.startswith('fe80:') or ip.startswith('ff02:') or ':' in ip:
                        continue
                    
                    # Ignorer les IPs externes (uniquement le réseau local)
                    if not self.is_private_ip(ip):
                        continue
                    
                    # Ignorer les IPs multicast/broadcast
                    if ip.startswith('224.') or ip.startswith('239.'):
                        continue
                    
                    # Ignorer ton propre système
                    if ip == self.mon_ip:
                        continue
                    
                    # Calculer la taille basée sur le trafic
                    total_bytes = (asset.total_bytes_sent or 0) + (asset.total_bytes_received or 0)
                    size = 40 + (min(total_bytes, 10**7) / 10**5)
                    if size > 90:
                        size = 90
                    
                    # Vérifier les alertes
                    alert = self._check_for_alerts(asset)
                    alert_count = alert['count'] if alert else 0
                    alert_severity = alert['severity'] if alert else None
                    
                    nodes.append({
                        'id': ip,
                        'label': ip,
                        'type': asset.device_type or 'unknown',
                        'location': 'internal',
                        'size': size,
                        'packets': 0,
                        'os': asset.os_info or 'unknown',
                        'manufacturer': asset.os_info or 'unknown',
                        'last_seen': asset.last_seen.isoformat() if asset.last_seen else None,
                        'total_bytes': total_bytes,
                        'open_ports': list(self.device_ports.get(ip, []))[:10],
                        'sites': asset.top_domains or [],
                        'alert_count': alert_count,
                        'alert_severity': alert_severity
                    })
                    
                    vrai_appareils += 1
                    
                    # Connexion ACRA -> appareil
                    edge_id = f"{self.mon_ip}-{ip}"
                    if edge_id not in edge_ids:
                        weight = 3 if asset.device_type == 'router' else 2
                        edges.append({
                            'id': edge_id,
                            'from': self.mon_ip,
                            'to': ip,
                            'weight': weight,
                            'traffic': total_bytes
                        })
                        edge_ids.add(edge_id)
                    
                    # Publier l'alerte si présente
                    if alert:
                        bus.publish('alert_update', {
                            'ip': ip,
                            'severity': alert['severity'],
                            'count': alert['count']
                        })
                
                print(f"[ACRA] 📊 Topologie: {vrai_appareils} appareils internes sur {len(assets)} actifs")
            
            # Publier via EventBus (en dehors du contexte DB)
            bus.publish_scapy_topology({
                'nodes': nodes,
                'edges': edges
            })
            
        except Exception as e:
            print(f"[ACRA] ❌ Erreur publication topologie: {e}")

    def run(self):
        """Lance le scanner et le sniffer en parallèle"""
        # Thread pour la découverte ARP
        t = threading.Thread(target=self.discovery_loop)
        t.daemon = True
        t.start()

        # Sniffing
        print(f"[ACRA] 🎯 Sniffing démarré sur {self.interface}...")
        try:
            scapy.sniff(iface=self.interface, prn=self.packet_callback, store=0)
        except Exception as e:
            print(f"[ACRA] ❌ Erreur sniffing: {e}")

def start_ingestion(app):
    """Fonction utilitaire pour lancer le service depuis app.py"""
    if os.getenv('DISABLE_NETWORK_INGESTION', 'False').lower() == 'true':
        print("[ACRA] ⏸️ Ingestion réseau désactivée")
        return
    
    interface = app.config.get('NETWORK_INTERFACE', 'eth0')
    ip_range = app.config.get('NETWORK_RANGE', '192.168.1.0/24')
    
    scanner = NetworkScannerService(app, interface, ip_range)
    
    main_thread = threading.Thread(target=scanner.run)
    main_thread.daemon = True
    main_thread.start()
    
    print(f"[ACRA] ✅ Service d'ingestion démarré sur {interface}")
    return scanner

# Pour compatibilité avec l'ancien code
TopologyCapture = NetworkScannerService

# Point d'entrée pour exécution directe (conteneur Docker)
if __name__ == "__main__":
    from flask import Flask
    app = Flask(__name__)
    
    # Configuration de la base de données
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://acra_admin:changeme123@localhost:5432/acra')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Configuration réseau
    app.config['NETWORK_INTERFACE'] = os.getenv('NETWORK_INTERFACE', 'eth0')
    app.config['NETWORK_RANGE'] = os.getenv('NETWORK_RANGE', '192.168.1.0/24')
    
    # Initialiser les extensions
    from src.extensions import db
    db.init_app(app)
    
    print(f"[ACRA] 🔧 Configuration DB: {app.config['SQLALCHEMY_DATABASE_URI']}")
    
    # Démarrer l'ingestion
    start_ingestion(app)
    
    # Garder le thread principal en vie
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[ACRA] Arrêt demandé")
        sys.exit(0)
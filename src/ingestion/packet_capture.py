import scapy.all as scapy
from datetime import datetime, timedelta
import time
import threading
from src.extensions import db
from src.models import NetworkAsset, NetworkFlow
from flask import current_app

class NetworkScannerService:
    def __init__(self, app, interface="eth0", ip_range="192.168.1.0/24"):
        self.app = app
        self.interface = interface
        self.ip_range = ip_range
        self.running = True

    def discovery_loop(self):
        """Boucle de scan ARP pour détecter les appareils (UC 'Temps Réel')"""
        with self.app.app_context():
            while self.running:
                try:
                    # Scan ARP : ff:ff:ff:ff:ff:ff demande qui possède ces IPs
                    print(f"[*] Scan ARP en cours sur {self.ip_range}...")
                    ans, _ = scapy.srp(
                        scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.ip_range), 
                        timeout=2, 
                        verbose=False,
                        iface=self.interface
                    )
                    
                    found_ips = []
                    for _, rcv in ans:
                        ip = rcv.psrc
                        mac = rcv.hwsrc
                        found_ips.append(ip)
                        
                        asset = NetworkAsset.query.filter_by(ip_address=ip).first()
                        if not asset:
                            # Nouvel appareil trouvé !
                            asset = NetworkAsset(
                                ip_address=ip, 
                                mac_address=mac, 
                                status='online',
                                last_seen=datetime.utcnow(),
                                asset_type='internal'
                            )
                            db.session.add(asset)
                        else:
                            # Appareil connu, on rafraîchit
                            asset.status = 'online'
                            asset.last_seen = datetime.utcnow()
                    
                    # Logique de passage au rouge (offline)
                    # On cherche les assets qui n'ont pas été vus dans ce scan
                    all_assets = NetworkAsset.query.filter_by(status='online').all()
                    for asset in all_assets:
                        if asset.ip_address not in found_ips:
                            # Si non vu depuis 2 mins, on passe offline
                            if (datetime.utcnow() - asset.last_seen).total_seconds() > 120:
                                asset.status = 'offline'

                    db.session.commit()
                except Exception as e:
                    print(f"[!] Erreur Scan: {e}")
                    db.session.rollback()
                
                time.sleep(30)

    def packet_callback(self, packet):
        """Analyse chaque paquet pour le trafic Mo et les sites (DNS)"""
        with self.app.app_context():
            try:
                if packet.haslayer(scapy.IP):
                    ip_src = packet[scapy.IP].src
                    size = len(packet)
                    
                    # 1. Mise à jour du volume de données (Mo)
                    asset = NetworkAsset.query.filter_by(ip_address=ip_src).first()
                    if asset:
                        asset.total_bytes_sent = (asset.total_bytes_sent or 0) + size
                        
                        # 2. Capture des sites visités (UC 'Savoir ce qui est fait')
                        if packet.haslayer(scapy.DNSQR):
                            # On récupère le nom de domaine (ex: google.com)
                            domain = packet[scapy.DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                            
                            # On met à jour la liste JSON sans doublons
                            current_sites = list(asset.top_domains or [])
                            if domain not in current_sites:
                                current_sites.append(domain)
                                # On garde uniquement les 10 plus récents
                                asset.top_domains = current_sites[-10:]
                        
                        db.session.commit()
            except Exception as e:
                # On évite de print à chaque paquet pour ne pas saturer la console
                pass

    def run(self):
        """Lance le scanner et le sniffer en parallèle"""
        # Thread pour la découverte ARP
        t = threading.Thread(target=self.discovery_loop)
        t.daemon = True
        t.start()

        # Sniffing (bloquant)
        print(f"[*] Sniffing démarré sur {self.interface}...")
        scapy.sniff(iface=self.interface, prn=self.packet_callback, store=0)

def start_ingestion(app):
    """Fonction utilitaire pour lancer le service depuis app.py"""
    # Récupération config depuis .env ou config.py
    interface = app.config.get('NETWORK_INTERFACE', 'eth0')
    ip_range = app.config.get('NETWORK_RANGE', '192.168.1.0/24')
    
    scanner = NetworkScannerService(app, interface, ip_range)
    # Lancement dans un thread pour ne pas bloquer Flask
    main_thread = threading.Thread(target=scanner.run)
    main_thread.daemon = True
    main_thread.start()
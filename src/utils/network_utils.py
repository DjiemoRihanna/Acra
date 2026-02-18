"""
Utilitaires réseau pour ACRA SOC
Détection automatique des interfaces et IPs
"""
import netifaces
import socket
import subprocess
import re

def get_soc_ip():
    """
    Détecte l'IP réelle du serveur SOC sur les interfaces physiques.
    Priorité : Ethernet, puis Wi-Fi, puis VM Bridges.
    """
    # Liste des interfaces courantes (Kali, Ubuntu, VM)
    interfaces = ['eth0', 'wlan0', 'enp0s3', 'ens33', 'enp2s0', 'eth1', 'br0', 'wlp2s0', 'wlp3s0']
    
    for iface in interfaces:
        try:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                # On ignore l'adresse de boucle locale
                if ip != '127.0.0.1':
                    return ip
        except (ValueError, KeyError):
            continue
            
    # Si aucune interface physique n'est trouvée, on tente la passerelle par défaut
    try:
        gws = netifaces.gateways()
        default_iface = gws['default'][netifaces.AF_INET][1]
        return netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]['addr']
    except Exception:
        return "127.0.0.1"

def get_soc_interface():
    """
    Détecte l'interface réseau principale
    """
    try:
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][1]
    except Exception:
        # Fallback: essayer de trouver la première interface avec une IP
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            if iface == 'lo':
                continue
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return iface
            except:
                pass
    return 'eth0'  # Fallback ultime

def get_network_range():
    """
    Détecte automatiquement la plage réseau à partir de l'IP et du masque
    """
    try:
        iface = get_soc_interface()
        addrs = netifaces.ifaddresses(iface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        
        # Convertir le masque en CIDR
        cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        
        # Calculer le réseau
        ip_parts = list(map(int, ip.split('.')))
        mask_parts = list(map(int, netmask.split('.')))
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        network = '.'.join(map(str, network_parts))
        
        return f"{network}/{cidr}"
    except Exception:
        return "192.168.1.0/24"  # Fallback

def is_port_open(ip, port, timeout=1):
    """
    Vérifie si un port est ouvert sur une IP
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_mac_from_ip(ip):
    """
    Récupère l'adresse MAC à partir d'une IP (ARP)
    """
    try:
        # Commande ARP
        result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
        if result.returncode == 0:
            # Parse la sortie
            match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', 
                            result.stdout)
            if match:
                return match.group(1)
    except:
        pass
    return None
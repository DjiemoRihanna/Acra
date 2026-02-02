import netifaces

def get_soc_ip():
    """
    Détecte l'IP réelle du serveur SOC sur les interfaces physiques.
    Priorité : Ethernet, puis Wi-Fi, puis VM Bridges.
    """
    # Liste des interfaces courantes (Kali, Ubuntu, VM)
    interfaces = ['eth0', 'wlan0', 'enp0s3', 'eth1', 'br0']
    
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
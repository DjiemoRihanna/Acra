from datetime import datetime, timedelta
from src.models import NetworkAsset, NetworkFlow
from src.extensions import db

def get_current_traffic_mb(ip_address, minutes=60):
    """Calcule le volume de trafic réel des X dernières minutes pour une IP"""
    time_threshold = datetime.utcnow() - timedelta(minutes=minutes)
    
    # On somme orig_bytes et resp_bytes dans la table NetworkFlow (remplie par Zeek)
    flows = NetworkFlow.query.filter(
        NetworkFlow.source_ip == ip_address,
        NetworkFlow.ts >= time_threshold
    ).all()
    
    total_bytes = sum((f.orig_bytes or 0) + (f.resp_bytes or 0) for f in flows)
    return total_bytes / (1024 * 1024) # Retourne en MB

def calculate_ueba_score(ip_address):
    """Génère le score d'anomalie comportementale (0-100)"""
    asset = NetworkAsset.query.filter_by(ip_address=ip_address).first()
    
    if not asset or not asset.avg_traffic_mb or asset.avg_traffic_mb == 0:
        return 10  # Score par défaut pour nouvel asset

    current_usage = get_current_traffic_mb(ip_address)
    
    # Calcul du ratio par rapport à la moyenne historique
    ratio = current_usage / asset.avg_traffic_mb

    if ratio < 1.3: return 0    # Normal
    if ratio < 2.0: return 20   # Légère augmentation
    if ratio < 5.0: return 50   # Augmentation suspecte
    if ratio < 10.0: return 80  # Forte suspicion d'anomalie
    return 100                 # Explosion de trafic (Exfiltration/Attaque)

def global_baseline_update():
    """Script à appeler via un worker pour mettre à jour les moyennes historiques"""
    assets = NetworkAsset.query.all()
    for asset in assets:
        # On calcule la moyenne sur les 24 dernières heures par exemple
        yesterday = datetime.utcnow() - timedelta(days=1)
        flows = NetworkFlow.query.filter(
            NetworkFlow.source_ip == asset.ip_address,
            NetworkFlow.ts >= yesterday
        ).all()
        
        if flows:
            total_mb = sum((f.orig_bytes or 0) + (f.resp_bytes or 0) for f in flows) / (1024 * 1024)
            # Moyenne glissante simple : (Ancienne * 6 + Nouvelle) / 7
            asset.avg_traffic_mb = ((asset.avg_traffic_mb * 6) + total_mb) / 7
            db.session.commit()
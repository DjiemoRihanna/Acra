from flask import Blueprint, jsonify, render_template  # Ajout de render_template
from flask_login import login_required
import netifaces
from src.models import NetworkAsset
from src.extensions import db

network_bp = Blueprint('network', __name__)

# --- 1. LA VUE (L'INTERFACE HTML) ---
@network_bp.route('/topology')
@login_required
def topology_view():
    """Affiche la page de la carte interactive."""
    return render_template('network/topology.html')

# --- 2. L'API (LES DONNÉES JSON) ---
@network_bp.route('/adata')  # URL différente pour le JSON
@login_required
def get_topology_data():
    """Renvoie les données des nœuds et des liens pour Cytoscape.js."""
    try:
        # 1. Détection de la Gateway
        default_gw_ip = "192.168.1.1"
        try:
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                default_gw_ip = gws['default'][netifaces.AF_INET][0]
        except Exception:
            pass

        assets = NetworkAsset.query.all()
        nodes = []
        edges = []

        gw_asset = NetworkAsset.query.filter_by(ip_address=default_gw_ip).first()
        master_id = str(gw_asset.id) if gw_asset else "virtual_gw"

        if not gw_asset:
            nodes.append({
                "data": {
                    "id": "virtual_gw",
                    "label": f"ROUTEUR\n({default_gw_ip})",
                    "device_type": "router",
                    "status": "online",
                    "ip": default_gw_ip,
                    "usage_mb": 0,
                    "sites": []
                }
            })

        for asset in assets:
            asset_data = asset.to_dict()
            nodes.append({
                "data": {
                    "id": str(asset_data["id"]),
                    "label": f"{asset_data['label']}\n{asset_data['usage_mb']} MB",
                    "ip": asset_data["ip"],
                    "mac": asset_data["mac"],
                    "device_type": asset_data["device_type"],
                    "status": asset_data["status"],
                    "usage": f"{asset_data['usage_mb']} MB",
                    "os": asset_data["os"],
                    "sites": asset_data["sites"],
                    "last_seen": asset_data["last_seen_human"]
                }
            })

            if asset.ip_address != default_gw_ip:
                edges.append({
                    "data": {
                        "id": f"e_{asset.id}",
                        "source": str(asset.id),
                        "target": master_id
                    }
                })

        return jsonify({
            "status": "success", 
            "nodes": nodes, 
            "edges": edges,
            "count": len(assets)
        })

    except Exception as e:
        print(f"[-] ERREUR API TOPOLOGIE: {str(e)}")
        return jsonify({"status": "error", "message": "Erreur SQL ou Data"}), 500
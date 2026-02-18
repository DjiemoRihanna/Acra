"""
API REST pour les données réseau
Endpoints pour la topologie et les appareils
"""
from flask import Blueprint, jsonify, request, current_app, render_template
from src.ingestion.packet_capture import TopologyCapture
from src.core.event_bus import bus
from src.models import NetworkAsset
from flask_login import login_required
import json
import logging
from datetime import datetime, timedelta

# ==========================================================
# BLUEPRINT POUR LES PAGES HTML (sans préfixe /api)
# ==========================================================
network_html_bp = Blueprint('network_html', __name__)

@network_html_bp.route('/network/topology')
@login_required
def topology_view():
    """Page HTML de la topologie réseau interactive"""
    # Récupérer les assets depuis la base de données
    assets = NetworkAsset.query.order_by(NetworkAsset.last_seen.desc()).all()
    
    # Convertir en dictionnaires pour le template
    devices = [asset.to_dict() for asset in assets]
    
    return render_template('network/topology.html', 
                          devices=devices,
                          now=datetime.utcnow())

# ==========================================================
# BLUEPRINT POUR L'API REST (avec préfixe /api/network)
# ==========================================================
network_bp = Blueprint('network', __name__, url_prefix='/api/network')

# Instance partagée du captureur (sera initialisée au premier appel)
_capture_instance = None

def get_capture():
    """Récupère ou initialise l'instance TopologyCapture (singleton)"""
    global _capture_instance
    if _capture_instance is None:
        _capture_instance = TopologyCapture()
        # Note: on ne démarre pas la capture ici car elle tourne dans un service séparé
    return _capture_instance

# --- ENDPOINTS POUR LA TOPOLOGIE ---

@network_bp.route('/topology', methods=['GET'])
def get_topology():
    """
    Récupère les données de topologie réseau pour Cytoscape.js
    """
    try:
        capture = get_capture()
        
        # Récupérer les données brutes
        topology_data = capture.get_topology_data()
        
        # Formater pour Cytoscape
        nodes = []
        for node in topology_data.get('nodes', []):
            nodes.append({
                'data': {
                    'id': node['id'],
                    'label': node['label'],
                    'ip': node['id'],
                    'device_type': node.get('type', 'unknown'),
                    'location': node.get('location', 'external'),
                    'status': 'online',
                    'usage': f"{node.get('size', 0):.1f} MB",
                    'total_bytes': node.get('size', 0) * 1024 * 1024,  # MB -> bytes
                    'total_packets': node.get('packets', 0),
                    'os': node.get('os', 'unknown'),
                    'manufacturer': node.get('manufacturer', 'unknown'),
                    'last_seen': node.get('last_seen', datetime.now().isoformat())
                }
            })
        
        edges = []
        for edge in topology_data.get('edges', []):
            edges.append({
                'data': {
                    'id': f"{edge['from']}-{edge['to']}",
                    'source': edge['from'],
                    'target': edge['to'],
                    'label': edge.get('label', ''),
                    'weight': 1
                }
            })
        
        return jsonify({
            'status': 'success',
            'nodes': nodes,
            'edges': edges,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"Erreur récupération topologie: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@network_bp.route('/devices', methods=['GET'])
def get_devices():
    """
    Récupère la liste détaillée de tous les appareils détectés
    ---
    parameters:
      - name: type
        in: query
        type: string
        description: Filtrer par type d'appareil (router, server, etc.)
      - name: location
        in: query
        type: string
        description: Filtrer par localisation (internal/external)
      - name: limit
        in: query
        type: integer
        description: Nombre maximum de résultats
    """
    try:
        capture = get_capture()
        limit = request.args.get('limit', default=100, type=int)
        device_type = request.args.get('type')
        location = request.args.get('location')
        
        devices = []
        for ip, device in capture.devices.items():
            # Appliquer les filtres
            if device_type and device.get('device_type') != device_type:
                continue
            if location and device.get('location') != location:
                continue
                
            devices.append({
                'ip': ip,
                'mac': device.get('mac'),
                'device_type': device.get('device_type', 'unknown'),
                'os': device.get('os', 'unknown'),
                'manufacturer': device.get('manufacturer', 'unknown'),
                'location': device.get('location', 'external'),
                'total_bytes': device.get('total_bytes', 0),
                'total_packets': device.get('total_packets', 0),
                'open_ports': list(device.get('open_ports', [])),
                'behaviors': device.get('behaviors', []),
                'first_seen': device.get('first_seen'),
                'last_seen': device.get('last_seen')
            })
            
            if len(devices) >= limit:
                break
        
        return jsonify({
            'status': 'success',
            'count': len(devices),
            'devices': devices
        })
        
    except Exception as e:
        current_app.logger.error(f"Erreur récupération appareils: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@network_bp.route('/devices/<ip>', methods=['GET'])
def get_device_detail(ip):
    """
    Récupère les détails d'un appareil spécifique
    """
    try:
        capture = get_capture()
        
        if ip not in capture.devices:
            return jsonify({
                'status': 'error',
                'message': f'Appareil {ip} non trouvé'
            }), 404
        
        device = capture.devices[ip]
        
        # Récupérer l'historique des paquets
        history = capture.packet_history.get(ip, [])
        
        # Calculer le débit moyen
        avg_rate = 0
        if len(history) > 1:
            time_span = (datetime.fromisoformat(history[-1]['timestamp']) - 
                        datetime.fromisoformat(history[0]['timestamp'])).total_seconds()
            if time_span > 0:
                total_bytes = sum(p['size'] for p in history)
                avg_rate = total_bytes / time_span
        
        return jsonify({
            'status': 'success',
            'device': {
                'ip': ip,
                'mac': device.get('mac'),
                'device_type': device.get('device_type', 'unknown'),
                'os': device.get('os', 'unknown'),
                'manufacturer': device.get('manufacturer', 'unknown'),
                'location': device.get('location', 'external'),
                'total_bytes': device.get('total_bytes', 0),
                'total_packets': device.get('total_packets', 0),
                'open_ports': list(device.get('open_ports', [])),
                'behaviors': device.get('behaviors', []),
                'first_seen': device.get('first_seen'),
                'last_seen': device.get('last_seen'),
                'avg_rate_bps': avg_rate,
                'connections': device.get('connections', [])[-20:]  # Dernières 20 connexions
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Erreur récupération appareil {ip}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@network_bp.route('/stats', methods=['GET'])
def get_network_stats():
    """
    Récupère les statistiques réseau globales
    """
    try:
        capture = get_capture()
        
        total_bytes = 0
        total_packets = 0
        devices_count = len(capture.devices)
        devices_by_type = {}
        devices_by_location = {'internal': 0, 'external': 0}
        
        for ip, device in capture.devices.items():
            total_bytes += device.get('total_bytes', 0)
            total_packets += device.get('total_packets', 0)
            
            # Compter par type
            d_type = device.get('device_type', 'unknown')
            devices_by_type[d_type] = devices_by_type.get(d_type, 0) + 1
            
            # Compter par location
            location = device.get('location', 'external')
            devices_by_location[location] = devices_by_location.get(location, 0) + 1
        
        # Calculer le débit actuel (dernière minute)
        current_rate = 0
        now = datetime.now()
        one_minute_ago = now - timedelta(minutes=1)
        
        recent_bytes = 0
        for ip, history in capture.packet_history.items():
            for pkt in history:
                try:
                    pkt_time = datetime.fromisoformat(pkt['timestamp'])
                    if pkt_time > one_minute_ago:
                        recent_bytes += pkt.get('size', 0)
                except:
                    pass
        
        current_rate = recent_bytes / 60  # bytes/s
        
        return jsonify({
            'status': 'success',
            'stats': {
                'total_devices': devices_count,
                'total_bytes': total_bytes,
                'total_packets': total_packets,
                'current_rate_bps': current_rate,
                'current_rate_mbps': current_rate * 8 / 1_000_000,  # Mbps
                'devices_by_type': devices_by_type,
                'devices_by_location': devices_by_location,
                'timestamp': datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Erreur récupération stats: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@network_bp.route('/flows/recent', methods=['GET'])
def get_recent_flows():
    """
    Récupère les flux réseau récents (pour le graphique temps réel)
    """
    try:
        capture = get_capture()
        limit = request.args.get('limit', default=50, type=int)
        
        flows = []
        for ip, history in capture.packet_history.items():
            for pkt in history[-limit:]:
                flows.append({
                    'timestamp': pkt.get('timestamp'),
                    'src_ip': pkt.get('src_ip'),
                    'dst_ip': pkt.get('dst_ip'),
                    'size': pkt.get('size', 0),
                    'direction': pkt.get('direction', 'unknown')
                })
        
        # Trier par timestamp (plus récent d'abord)
        flows.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify({
            'status': 'success',
            'count': len(flows[:limit]),
            'flows': flows[:limit]
        })
        
    except Exception as e:
        current_app.logger.error(f"Erreur récupération flows: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# --- ENDPOINTS POUR LE CONTRÔLE (ADMIN) ---

@network_bp.route('/control/scan', methods=['POST'])
def trigger_scan():
    """
    Déclenche un scan réseau manuel (ARP scan)
    Nécessite des privilèges admin
    """
    # Vérifier les permissions (à implémenter avec votre système d'auth)
    # if not current_user.has_role('admin'):
    #     return jsonify({'status': 'error', 'message': 'Permission denied'}), 403
    
    try:
        # Publier un événement pour demander un scan
        bus.publish('system:control', {
            'action': 'network_scan',
            'requested_by': 'api',
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'status': 'success',
            'message': 'Scan réseau déclenché'
        })
        
    except Exception as e:
        current_app.logger.error(f"Erreur déclenchement scan: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@network_bp.route('/control/clear-cache', methods=['POST'])
def clear_cache():
    """
    Vide le cache des appareils (admin only)
    """
    try:
        capture = get_capture()
        capture.devices.clear()
        capture.packet_history.clear()
        
        return jsonify({
            'status': 'success',
            'message': 'Cache vidé'
        })
        
    except Exception as e:
        current_app.logger.error(f"Erreur vidage cache: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# --- WEBSOCKET EVENTS (pour le temps réel) ---

def register_socketio_events(socketio):
    """Enregistre les événements WebSocket pour la topologie"""
    
    @socketio.on('request_topology')
    def handle_topology_request():
        """Le client demande un rafraîchissement de la topologie"""
        try:
            capture = get_capture()
            topology_data = capture.get_topology_data()
            
            # Formater pour l'envoi
            nodes = []
            for node in topology_data.get('nodes', []):
                nodes.append({
                    'id': node['id'],
                    'label': node['label'],
                    'device_type': node.get('type', 'unknown'),
                    'location': node.get('location', 'external'),
                    'total_bytes': node.get('size', 0) * 1024 * 1024,
                    'total_packets': node.get('packets', 0),
                    'os': node.get('os', 'unknown'),
                    'manufacturer': node.get('manufacturer', 'unknown'),
                    'last_seen': node.get('last_seen')
                })
            
            socketio.emit('scapy_topology', {
                'nodes': nodes,
                'edges': topology_data.get('edges', [])
            }, room=request.sid)
            
        except Exception as e:
            current_app.logger.error(f"Erreur envoi topologie: {e}")
    
    @socketio.on('request_device_details')
    def handle_device_details(data):
        """Le client demande les détails d'un appareil spécifique"""
        ip = data.get('ip')
        if not ip:
            return
        
        try:
            capture = get_capture()
            if ip in capture.devices:
                device = capture.devices[ip]
                socketio.emit('device_details', {
                    'ip': ip,
                    'device': {
                        'ip': ip,
                        'mac': device.get('mac'),
                        'device_type': device.get('device_type'),
                        'os': device.get('os'),
                        'manufacturer': device.get('manufacturer'),
                        'total_bytes': device.get('total_bytes'),
                        'total_packets': device.get('total_packets'),
                        'open_ports': list(device.get('open_ports', [])),
                        'behaviors': device.get('behaviors', []),
                        'last_seen': device.get('last_seen')
                    }
                }, room=request.sid)
        except Exception as e:
            current_app.logger.error(f"Erreur envoi détails: {e}")
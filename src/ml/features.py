"""
Module ML - Extraction des features pour les modèles
"""
import numpy as np
from datetime import datetime, timedelta
from src.models import NetworkFlow

class FeatureExtractor:
    """
    Extraction des features à partir des flux réseau
    """
    
    def __init__(self):
        self.feature_names = [
            'bytes_sent',
            'bytes_received',
            'duration',
            'src_port',
            'dst_port',
            'src_internal',
            'dst_internal',
            'protocol_encoded',
            'hour',
            'weekday',
            'packet_rate',
            'bytes_rate',
            'src_connections_last_hour',
            'dst_connections_last_hour',
            'is_suspicious_port'
        ]
    
    def extract_from_flow(self, flow_data):
        """
        Extrait les features d'un flux (format dict ou objet)
        """
        features = []
        
        # 1. Bytes sent/received
        bytes_sent = flow_data.get('orig_bytes', 0) if isinstance(flow_data, dict) else getattr(flow_data, 'orig_bytes', 0)
        bytes_received = flow_data.get('resp_bytes', 0) if isinstance(flow_data, dict) else getattr(flow_data, 'resp_bytes', 0)
        features.append(bytes_sent)
        features.append(bytes_received)
        
        # 2. Duration
        duration = flow_data.get('duration', 0) if isinstance(flow_data, dict) else getattr(flow_data, 'duration', 0)
        features.append(duration)
        
        # 3. Ports
        src_port = flow_data.get('source_port', 0) if isinstance(flow_data, dict) else getattr(flow_data, 'source_port', 0)
        dst_port = flow_data.get('dest_port', 0) if isinstance(flow_data, dict) else getattr(flow_data, 'dest_port', 0)
        features.append(src_port)
        features.append(dst_port)
        
        # 4. Internal flags
        src_internal = flow_data.get('source_is_internal', False) if isinstance(flow_data, dict) else getattr(flow_data, 'source_is_internal', False)
        dst_internal = flow_data.get('dest_is_internal', False) if isinstance(flow_data, dict) else getattr(flow_data, 'dest_is_internal', False)
        features.append(1 if src_internal else 0)
        features.append(1 if dst_internal else 0)
        
        # 5. Protocol encoding
        protocol = flow_data.get('protocol', '') if isinstance(flow_data, dict) else getattr(flow_data, 'protocol', '')
        features.append(self._encode_protocol(protocol))
        
        # 6. Temporal features
        ts = flow_data.get('ts') if isinstance(flow_data, dict) else getattr(flow_data, 'ts', datetime.utcnow())
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        features.append(ts.hour)
        features.append(ts.weekday())
        
        # 7. Rate features
        if duration > 0:
            packet_rate = 1 / duration  # Simplifié
            bytes_rate = (bytes_sent + bytes_received) / duration
        else:
            packet_rate = 0
            bytes_rate = 0
        features.append(packet_rate)
        features.append(bytes_rate)
        
        # 8. Context features
        features.append(self._count_recent_connections(flow_data, is_src=True))
        features.append(self._count_recent_connections(flow_data, is_src=False))
        
        # 9. Suspicious port
        features.append(1 if self._is_suspicious_port(dst_port) else 0)
        
        return np.array(features, dtype=np.float32)
    
    def _encode_protocol(self, protocol):
        """Encode le protocole en nombre"""
        protocol_map = {
            'tcp': 1,
            'udp': 2,
            'icmp': 3,
            'http': 4,
            'https': 5,
            'dns': 6,
            'ssh': 7,
            'ftp': 8,
            'smtp': 9,
            'unknown': 0
        }
        return protocol_map.get(protocol.lower() if protocol else 'unknown', 0)
    
    def _count_recent_connections(self, flow_data, is_src=True, minutes=60):
        """Compte les connexions récentes pour cette IP"""
        # À implémenter avec une requête DB
        # Pour l'instant, valeur par défaut
        return 0
    
    def _is_suspicious_port(self, port):
        """Vérifie si le port est suspect"""
        suspicious_ports = [22, 23, 445, 3389, 1433, 3306, 5432, 27017]
        return port in suspicious_ports
    
    def get_feature_names(self):
        """Retourne les noms des features"""
        return self.feature_names
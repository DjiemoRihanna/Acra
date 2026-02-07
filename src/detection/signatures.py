import socket
from src.ingestion.suricata_stream import stream_alerts
from src.detection.ti_client import TIClient
from src.core.circuit_breaker import evaluate_and_block

class SignatureAnalyzer:
    def __init__(self):
        self.ti = TIClient()

    def get_hostname(self, ip):
        """Résolution DNS inversée pour identifier la machine."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Machine Inconnue"

    def run(self):
        for event in stream_alerts():
            alert_data = event.get('alert', {})
            src_ip = event.get('src_ip')
            dest_ip = event.get('dest_ip')
            
            # Identification des machines
            src_name = self.get_hostname(src_ip)
            
            prio = alert_data.get('priority') or alert_data.get('severity')
            signature = alert_data.get('signature')

            # 1. Obtenir réputation
            ti_score = self.ti.get_ip_reputation(src_ip)
            
            # 2. Calculer score et vérifier Coupe-Circuit
            final_score = evaluate_and_block(
                ip=src_ip, 
                ti_score=ti_score, 
                priority=prio
            )

            print(f"\n[DÉTECTION RÉELLE]")
            print(f"🚨 Menace : {signature}")
            print(f"🖥️  Origine : {src_ip} ({src_name}) -> Dest: {dest_ip}")
            print(f"📊 Priorité: {prio} | Score TI: {ti_score} | SCORE FINAL: {final_score}")

if __name__ == "__main__":
    analyzer = SignatureAnalyzer()
    analyzer.run()
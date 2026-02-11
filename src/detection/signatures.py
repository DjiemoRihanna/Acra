import logging
import socket
from src.ingestion.suricata_stream import stream_alerts
from src.detection.ti_client import TIClient
from src.core.circuit_breaker import evaluate_and_block

# CONFIGURATION DU LOGGING GLOBAL
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("logs/acra.log"), # Écrit dans un fichier
        logging.StreamHandler()              # Affiche dans la console
    ]
)
logger = logging.getLogger(__name__)

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Machine Inconnue"

def process_alerts():
    ti_client = TIClient()
    logger.info("Moteur d'analyse NDR démarré...")

    for alert_data in stream_alerts():
        try:
            alert = alert_data.get("alert", {})
            src_ip = alert_data.get("src_ip")
            if not src_ip: continue

            priority = alert.get("priority", 3)
            signature = alert.get("signature", "N/A")
            
            ti_score = ti_client.get_score(src_ip)
            final_score = evaluate_and_block(src_ip, ti_score, priority)

            # Remplacement des print par logger.info
            logger.info(f"DÉTECTION : {signature} | Origine: {src_ip} ({get_hostname(src_ip)}) | Score: {final_score}")

            if final_score == 100:
                logger.critical(f"ACTION : Blocage immédiat requis pour {src_ip}")

        except Exception as e:
            logger.error(f"Erreur lors du traitement de l'alerte : {e}")

if __name__ == "__main__":
    process_alerts()
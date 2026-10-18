import logging
import sys

from src.clients.db_client import bd_result
from src.config import cloud_id, folder_id, validate_configuration
from src.metrics import send_metrics
from src.scanner import live_scan

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", stream=sys.stdout, force=True
)
logger = logging.getLogger(__name__)


def main():
    validate_configuration()
    result = live_scan(str(folder_id), str(cloud_id))
    if result.buckets:
        bd_result(result)
        send_metrics(result)
        logger.info("")
        logger.info("==================== ДОСТУПНЫЕ СЕРВИСЫ ====================")
        logger.info("Pushgateway (метрики):       http://localhost:9091/metrics")
        logger.info("Prometheus (запросы):        http://localhost:9090")
        logger.info("Grafana (дашборды):          http://localhost:3000 (admin/admin)")
        logger.info("===========================================================")
        logger.info("")


if __name__ == "__main__":
    main()

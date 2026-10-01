from threading import Event

from app import create_app
from app.config import ProductionConfig


class MaintenanceWorkerConfig(ProductionConfig):
    ENABLE_MAINTENANCE_SCHEDULER = True


def main():
    create_app(MaintenanceWorkerConfig)
    Event().wait()


if __name__ == "__main__":
    main()
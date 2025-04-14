import json
import os

class USBMonitor:
    def __init__(self, callback):
        self.callback = callback
        # Placeholder for USB monitoring (requires platform-specific implementation)
        # For simplicity, assume manual triggering for now
        pass

def export_history(history, filename):
    try:
        with open(filename, "w") as f:
            json.dump(history, f)
        return True, "История экспортирована"
    except Exception as e:
        return False, f"Ошибка экспорта: {str(e)}"

def import_history(filename):
    try:
        with open(filename, "r") as f:
            return True, json.load(f)
    except Exception as e:
        return False, f"Ошибка импорта: {str(e)}"
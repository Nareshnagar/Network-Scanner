# scanner/history_manager.py

import json
import os
from datetime import datetime

def save_scan(scan_results):

    if not os.path.exists("scan_history"):
        os.makedirs("scan_history")

    filename = f"scan_history/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(scan_results, f, indent=4)

    return filename
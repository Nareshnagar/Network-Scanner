from flask import Flask, render_template, request, send_from_directory

from scanner.discovery import scan_network

from scanner.portscanner import (
    scan_target,
    scan_ports
)

from scanner.risk_engine import calculate_risk

from scanner.report_generator import generate_pdf_report

from scanner.history_manager import save_scan

app = Flask(__name__)

# ==========================================================
# GLOBAL STORAGE
# ==========================================================

stored_devices = []

stored_report = None

# ==========================================================
# EXTRACT PORT NUMBERS
# ==========================================================

def extract_port_numbers(ports):

    return [p["Port"] for p in ports]

# ==========================================================
# DEVICE DISCOVERY PROCESS
# ==========================================================

def process_discovery():

    discovered_devices = scan_network()

    final_results = []

    for device in discovered_devices:

        ip = device["IP"]

        # ==================================================
        # PORT SCAN
        # ==================================================

        open_ports = scan_ports(ip)

        # ==================================================
        # RISK ENGINE
        # ==================================================

        port_numbers = extract_port_numbers(open_ports)

        risk_data = calculate_risk(port_numbers)

        # ==================================================
        # STORE RESULTS
        # ==================================================

        device["ports"] = open_ports

        device["risk"] = risk_data

        final_results.append(device)

    # ======================================================
    # SAVE HISTORY
    # ======================================================

    save_scan(final_results)

    # ======================================================
    # GENERATE REPORT
    # ======================================================

    report_path = generate_pdf_report(final_results)

    return final_results, report_path

# ==========================================================
# PORT SCAN PROCESS
# ==========================================================

def process_port_scan(target_ip):

    ports = scan_target(target_ip)

    port_numbers = extract_port_numbers(ports)

    risk = calculate_risk(port_numbers)

    return ports, risk

# ==========================================================
# REPORT DOWNLOAD ROUTE
# ==========================================================

@app.route("/reports/<path:filename>", methods=["GET"])

def download_report(filename):

    return send_from_directory(
        "reports",
        filename,
        as_attachment=True
    )

# ==========================================================
# HOME ROUTE
# ==========================================================

@app.route("/", methods=["GET", "POST"])

def home():

    global stored_devices
    global stored_report

    # ======================================================
    # KEEP OLD RESULTS
    # ======================================================

    devices = stored_devices

    ports = []

    risk = None

    report_path = stored_report

    # ======================================================
    # HANDLE POST REQUEST
    # ======================================================

    if request.method == "POST":

        action = request.form.get("action")

        # ==================================================
        # DISCOVER DEVICES
        # ==================================================

        if action == "discover":

            final_results, report_path = process_discovery()

            stored_devices = final_results

            stored_report = report_path

            devices = stored_devices

        # ==================================================
        # SCAN SINGLE TARGET
        # ==================================================

        elif action == "scan_port":

            target_ip = request.form.get("target_ip")

            ports, risk = process_port_scan(target_ip)

    # ======================================================
    # RENDER PAGE
    # ======================================================

    return render_template(
        "index.html",
        devices=devices,
        ports=ports,
        risk=risk,
        report=report_path
    )

# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":

    app.run(debug=True)
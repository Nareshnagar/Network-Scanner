# scanner/report_generator.py

from fpdf import FPDF
from datetime import datetime
import os

def generate_pdf_report(scan_results):

    if not os.path.exists("reports"):
        os.makedirs("reports")

    filename = f"reports/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "AI Network Security Scan Report", ln=True, align="C")

    pdf.ln(10)

    for device in scan_results:

        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, f"IP: {device['IP']}", ln=True)

        pdf.set_font("Arial", "", 11)

        pdf.cell(200, 8, f"Hostname: {device['Hostname']}", ln=True)
        pdf.cell(200, 8, f"MAC: {device['MAC']}", ln=True)
        pdf.cell(200, 8, f"Vendor: {device['Vendor']}", ln=True)

        pdf.cell(200, 8, f"Open Ports: {device['ports']}", ln=True)

        pdf.cell(200, 8, f"Risk Score: {device['risk']['risk_score']}/100", ln=True)

        pdf.cell(200, 8, f"Threat Level: {device['risk']['threat_level']}", ln=True)

        pdf.multi_cell(
            0,
            8,
            "Reasons:\n" + "\n".join(device['risk']['reasons'])
        )

        pdf.ln(5)

    pdf.output(filename)

    return filename
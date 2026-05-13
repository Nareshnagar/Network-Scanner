# ==========================================================
# RISK ENGINE
# ==========================================================

def calculate_risk(open_ports):

    risk_score = 0

    reasons = []

    # ======================================================
    # HIGH RISK PORTS
    # ======================================================

    high_risk_ports = {
        21: "FTP",
        23: "Telnet",
        445: "SMB",
        3389: "RDP",
        3306: "MySQL"
    }

    # ======================================================
    # MEDIUM RISK PORTS
    # ======================================================

    medium_risk_ports = {
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        135: "MSRPC",
        139: "NetBIOS"
    }

    # ======================================================
    # SAFE PORTS
    # ======================================================

    safe_ports = {
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP Secure",
        993: "IMAPS",
        995: "POP3S"
    }

    # ======================================================
    # ANALYZE PORTS
    # ======================================================

    for port in open_ports:

        # HIGH RISK
        if port in high_risk_ports:

            risk_score += 25

            reasons.append(
                f"High-risk service exposed on port {port}"
            )

        # MEDIUM RISK
        elif port in medium_risk_ports:

            risk_score += 10

            reasons.append(
                f"Legacy mail/service port {port} open"
            )

        # SAFE PORTS
        elif port in safe_ports:

            risk_score += 1

    # ======================================================
    # TOO MANY OPEN PORTS
    # ======================================================

    if len(open_ports) >= 10:

        risk_score += 15

        reasons.append(
            "Large number of open ports detected"
        )

    # ======================================================
    # LIMIT SCORE
    # ======================================================

    if risk_score > 100:
        risk_score = 100

    # ======================================================
    # THREAT LEVEL
    # ======================================================

    if risk_score >= 70:

        threat_level = "CRITICAL"

    elif risk_score >= 45:

        threat_level = "HIGH"

    elif risk_score >= 20:

        threat_level = "MEDIUM"

    else:

        threat_level = "LOW"

    # ======================================================
    # NO RISKS
    # ======================================================

    if not reasons:

        reasons.append(
            "No major security risks detected"
        )

    # ======================================================
    # RETURN RESULT
    # ======================================================

    return {
        "risk_score": risk_score,
        "threat_level": threat_level,
        "reasons": reasons
    }
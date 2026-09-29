def analyze_security(tls_result, https_result):
    """
    Analyze basic HTTPS/TLS security configuration.

    This is a diagnostic tool, not a penetration test.
    """

    findings = []

    headers = https_result.get(
        "headers",
        {}
    )

    # Normalize header names
    normalized_headers = {
        key.lower(): value
        for key, value in headers.items()
    }

    # --------------------------------------------------------
    # TLS VERSION
    # --------------------------------------------------------

    tls_version = tls_result.get(
        "version"
    )

    if tls_version == "TLSv1.3":

        findings.append({
            "check": "TLS Version",
            "value": tls_version,
            "status": "PASS",
            "message": "Modern TLS version detected."
        })

    elif tls_version == "TLSv1.2":

        findings.append({
            "check": "TLS Version",
            "value": tls_version,
            "status": "PASS",
            "message": "TLS 1.2 detected."
        })

    elif tls_version:

        findings.append({
            "check": "TLS Version",
            "value": tls_version,
            "status": "WARNING",
            "message": "Older TLS version detected."
        })

    else:

        findings.append({
            "check": "TLS Version",
            "value": "Unavailable",
            "status": "WARNING",
            "message": "Could not determine TLS version."
        })

    # --------------------------------------------------------
    # CERTIFICATE
    # --------------------------------------------------------

    certificate = tls_result.get(
        "certificate",
        {}
    )

    certificate_valid = certificate.get(
        "valid"
    )

    days_remaining = certificate.get(
        "days_remaining"
    )

    if certificate_valid:

        findings.append({
            "check": "Certificate",
            "value": "VALID",
            "status": "PASS",
            "message": "TLS certificate is currently valid."
        })

    else:

        findings.append({
            "check": "Certificate",
            "value": "INVALID",
            "status": "WARNING",
            "message": "Certificate could not be verified as valid."
        })

    # --------------------------------------------------------
    # CERTIFICATE EXPIRY
    # --------------------------------------------------------

    if days_remaining is not None:

        if days_remaining > 30:

            findings.append({
                "check": "Certificate Expiry",
                "value": f"{days_remaining:.2f} days",
                "status": "PASS",
                "message": "Certificate has more than 30 days remaining."
            })

        elif days_remaining > 0:

            findings.append({
                "check": "Certificate Expiry",
                "value": f"{days_remaining:.2f} days",
                "status": "WARNING",
                "message": "Certificate expires within 30 days."
            })

        else:

            findings.append({
                "check": "Certificate Expiry",
                "value": "EXPIRED",
                "status": "WARNING",
                "message": "Certificate appears to be expired."
            })

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    https_status = https_result.get(
        "status"
    )

    if https_status is not None:

        if 200 <= https_status < 400:

            findings.append({
                "check": "HTTPS",
                "value": f"HTTP {https_status}",
                "status": "PASS",
                "message": "HTTPS endpoint responded successfully."
            })

        else:

            findings.append({
                "check": "HTTPS",
                "value": f"HTTP {https_status}",
                "status": "INFO",
                "message": "HTTPS endpoint responded with a non-success status."
            })

    else:

        findings.append({
            "check": "HTTPS",
            "value": "Unavailable",
            "status": "WARNING",
            "message": "HTTPS endpoint could not be reached."
        })

    # --------------------------------------------------------
    # HSTS
    # --------------------------------------------------------

    if "strict-transport-security" in normalized_headers:

        findings.append({
            "check": "HSTS",
            "value": normalized_headers[
                "strict-transport-security"
            ],
            "status": "PASS",
            "message": "Strict-Transport-Security header detected."
        })

    else:

        findings.append({
            "check": "HSTS",
            "value": "NOT DETECTED",
            "status": "WARNING",
            "message": "HSTS header was not detected."
        })

    # --------------------------------------------------------
    # X-FRAME-OPTIONS
    # --------------------------------------------------------

    if "x-frame-options" in normalized_headers:

        findings.append({
            "check": "X-Frame-Options",
            "value": normalized_headers[
                "x-frame-options"
            ],
            "status": "PASS",
            "message": "X-Frame-Options header detected."
        })

    else:

        findings.append({
            "check": "X-Frame-Options",
            "value": "NOT DETECTED",
            "status": "WARNING",
            "message": "X-Frame-Options header was not detected."
        })

    # --------------------------------------------------------
    # CONTENT TYPE
    # --------------------------------------------------------

    if "content-type" in normalized_headers:

        findings.append({
            "check": "Content-Type",
            "value": normalized_headers[
                "content-type"
            ],
            "status": "PASS",
            "message": "Content-Type header detected."
        })

    else:

        findings.append({
            "check": "Content-Type",
            "value": "NOT DETECTED",
            "status": "WARNING",
            "message": "Content-Type header was not detected."
        })

    # --------------------------------------------------------
    # X-CONTENT-TYPE-OPTIONS
    # --------------------------------------------------------

    if "x-content-type-options" in normalized_headers:

        findings.append({
            "check": "X-Content-Type-Options",
            "value": normalized_headers[
                "x-content-type-options"
            ],
            "status": "PASS",
            "message": "X-Content-Type-Options header detected."
        })

    else:

        findings.append({
            "check": "X-Content-Type-Options",
            "value": "NOT DETECTED",
            "status": "INFO",
            "message": "X-Content-Type-Options header was not detected."
        })

    # --------------------------------------------------------
    # REFERRER POLICY
    # --------------------------------------------------------

    if "referrer-policy" in normalized_headers:

        findings.append({
            "check": "Referrer-Policy",
            "value": normalized_headers[
                "referrer-policy"
            ],
            "status": "PASS",
            "message": "Referrer-Policy header detected."
        })

    else:

        findings.append({
            "check": "Referrer-Policy",
            "value": "NOT DETECTED",
            "status": "INFO",
            "message": "Referrer-Policy header was not detected."
        })

    # --------------------------------------------------------
    # PERMISSIONS POLICY
    # --------------------------------------------------------

    if "permissions-policy" in normalized_headers:

        findings.append({
            "check": "Permissions-Policy",
            "value": normalized_headers[
                "permissions-policy"
            ],
            "status": "PASS",
            "message": "Permissions-Policy header detected."
        })

    else:

        findings.append({
            "check": "Permissions-Policy",
            "value": "NOT DETECTED",
            "status": "INFO",
            "message": "Permissions-Policy header was not detected."
        })

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    pass_count = sum(
        1
        for finding in findings
        if finding["status"] == "PASS"
    )

    warning_count = sum(
        1
        for finding in findings
        if finding["status"] == "WARNING"
    )

    info_count = sum(
        1
        for finding in findings
        if finding["status"] == "INFO"
    )

    return {
        "findings": findings,
        "summary": {
            "pass": pass_count,
            "warning": warning_count,
            "info": info_count
        }
    }
import sys
import json

from dns_resolver import resolve_domain
from dns_records import get_dns_records
from dns_health import analyze_dns_health
from tcp import check_port
from http_checker import check_http
from tls import check_tls
from network import get_network_info
from security import analyze_security


# ============================================================
# CONFIGURATION
# ============================================================

VERSION = "5.3"

PORTS = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    53: "DNS"
}


# ============================================================
# DISPLAY HELPERS
# ============================================================

def print_header():

    print("=" * 60)
    print("              NETWORK DIAGNOSTIC TOOL v5.3")
    print("=" * 60)


def print_section(number, title):

    print()
    print(f"[{number}] {title}")
    print("-" * 35)


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # COMMAND LINE ARGUMENTS
    # --------------------------------------------------------

    json_mode = "--json" in sys.argv

    domain = None

    for argument in sys.argv[1:]:

        if not argument.startswith("--"):

            domain = argument
            break

    # --------------------------------------------------------
    # ASK FOR DOMAIN
    # --------------------------------------------------------

    if not domain:

        domain = input("Enter a domain: ").strip()

    domain = domain.strip()

    if not domain:

        print("Error: Domain cannot be empty.")
        return

    # Remove protocol/path if supplied

    domain = (
        domain
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    print_header()

    # ========================================================
    # REPORT
    # ========================================================

    report = {

        "tool":
            "Network Diagnostic Tool",

        "version":
            VERSION,

        "domain":
            domain

    }

    # ========================================================
    # 1. DNS RESOLUTION
    # ========================================================

    print_section(
        1,
        "DNS RESOLUTION"
    )

    print(
        f"Domain      : {domain}"
    )

    print()

    try:

        dns_result = resolve_domain(
            domain
        )

    except Exception as e:

        dns_result = {

            "ipv4": [],
            "ipv6": [],

            "error":
                str(e)

        }

    ipv4 = dns_result.get(
        "ipv4",
        []
    )

    ipv6 = dns_result.get(
        "ipv6",
        []
    )

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    print("IPv4 Addresses:")

    if ipv4:

        for address in ipv4:

            print(
                f"  → {address}"
            )

    else:

        print(
            "  → None found"
        )

    print()

    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    print("IPv6 Addresses:")

    if ipv6:

        for address in ipv6:

            print(
                f"  → {address}"
            )

    else:

        print(
            "  → None found"
        )

    print()

    # --------------------------------------------------------
    # DNS STATUS
    # --------------------------------------------------------

    if ipv4:

        print(
            "DNS         : SUCCESS"
        )

    else:

        print(
            "DNS         : FAILED"
        )

        if dns_result.get("error"):

            print(
                dns_result["error"]
            )

        else:

            print(
                "Could not resolve an IPv4 address."
            )

        return

    # --------------------------------------------------------
    # Save DNS
    # --------------------------------------------------------

    report["dns"] = {

        "ipv4":
            ipv4,

        "ipv6":
            ipv6

    }

    # ========================================================
    # 2. DNS RECORDS
    # ========================================================

    print_section(
        2,
        "DNS RECORDS"
    )

    try:

        records = get_dns_records(
            domain
        )

    except Exception as e:

        records = {

            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],

            "error":
                str(e)

        }

    report["dns"]["records"] = records

    # --------------------------------------------------------
    # A / AAAA / MX / NS
    # --------------------------------------------------------

    for record_type in [

        "A",
        "AAAA",
        "MX",
        "NS"

    ]:

        print()

        print(
            f"{record_type}:"
        )

        values = records.get(
            record_type,
            []
        )

        if values:

            for value in values:

                print(
                    f"  → {value}"
                )

        else:

            print(
                "  → None found"
            )

    # --------------------------------------------------------
    # TXT
    # --------------------------------------------------------

    print()

    print("TXT:")

    txt_records = records.get(
        "TXT",
        []
    )

    if txt_records:

        print(
            f"  → {len(txt_records)} record(s) found"
        )

    else:

        print(
            "  → None found"
        )

    # ========================================================
    # 3. DNS HEALTH ANALYSIS
    # ========================================================

    print_section(
        3,
        "DNS HEALTH ANALYSIS"
    )

    try:

        dns_health = analyze_dns_health(
            domain
        )

    except Exception as e:

        dns_health = {

            "findings": [],

            "records": {},

            "summary": {

                "pass": 0,
                "warning": 1,
                "info": 0

            },

            "error":
                str(e)

        }

    report["dns"]["health"] = dns_health

    # --------------------------------------------------------
    # DNS FINDINGS
    # --------------------------------------------------------

    for finding in dns_health.get(
        "findings",
        []
    ):

        check = finding.get(
            "check",
            "Unknown"
        )

        value = finding.get(
            "value",
            "N/A"
        )

        status = finding.get(
            "status",
            "INFO"
        )

        print(
            f"{check:<20}: "
            f"{value:<25} "
            f"{status}"
        )

    # --------------------------------------------------------
    # DNS SUMMARY
    # --------------------------------------------------------

    summary = dns_health.get(
        "summary",
        {}
    )

    print()

    print(
        "DNS Health Summary"
    )

    print(
        "-" * 35
    )

    print(
        f"PASS     : "
        f"{summary.get('pass', 0)}"
    )

    print(
        f"WARNING  : "
        f"{summary.get('warning', 0)}"
    )

    print(
        f"INFO     : "
        f"{summary.get('info', 0)}"
    )

    # ========================================================
    # 4. TCP PORT CHECK
    # ========================================================

    print_section(
        4,
        "TCP PORT CHECK"
    )

    tcp_results = {}

    target_ip = ipv4[0]

    for port, service in PORTS.items():

        try:

            result = check_port(
                target_ip,
                port
            )

        except Exception:

            result = {

                "status":
                    "CLOSED/FILTERED",

                "connection_time_ms":
                    None

            }

        status = result.get(
            "status",
            "CLOSED/FILTERED"
        )

        connection_time = result.get(
            "connection_time_ms"
        )

        tcp_results[str(port)] = {

            "service":
                service,

            "status":
                status,

            "connection_time_ms":
                connection_time

        }

        if connection_time is not None:

            print(
                f"Port {port:<3} "
                f"({service:<5}) : "
                f"{status} "
                f"[{connection_time:.2f} ms]"
            )

        else:

            print(
                f"Port {port:<3} "
                f"({service:<5}) : "
                f"{status}"
            )

    report["tcp"] = tcp_results

    # ========================================================
    # 5. HTTP
    # ========================================================

    print_section(
        5,
        "HTTP"
    )

    try:

        http_result = check_http(
            domain,
            secure=False
        )

    except Exception as e:

        http_result = {

            "status":
                None,

            "reason":
                str(e),

            "time":
                None,

            "headers":
                {}

        }

    print(
        f"Status Code : "
        f"{http_result.get('status')}"
    )

    print(
        f"Response    : "
        f"{http_result.get('reason')}"
    )

    if http_result.get("time") is not None:

        print(
            f"Time        : "
            f"{http_result['time']:.2f} ms"
        )

    else:

        print(
            "Time        : N/A"
        )

    report["http"] = {

        "status":
            http_result.get("status"),

        "reason":
            http_result.get("reason"),

        "response_time_ms":
            http_result.get("time")

    }

    # ========================================================
    # 6. HTTPS
    # ========================================================

    print_section(
        6,
        "HTTPS"
    )

    try:

        https_result = check_http(
            domain,
            secure=True
        )

    except Exception as e:

        https_result = {

            "status":
                None,

            "reason":
                str(e),

            "time":
                None,

            "headers":
                {}

        }

    print(
        f"Status Code : "
        f"{https_result.get('status')}"
    )

    print(
        f"Response    : "
        f"{https_result.get('reason')}"
    )

    if https_result.get("time") is not None:

        print(
            f"Time        : "
            f"{https_result['time']:.2f} ms"
        )

    else:

        print(
            "Time        : N/A"
        )

    report["https"] = {

        "status":
            https_result.get("status"),

        "reason":
            https_result.get("reason"),

        "response_time_ms":
            https_result.get("time"),

        "headers":
            https_result.get(
                "headers",
                {}
            )

    }

    # ========================================================
    # 7. TLS INFORMATION
    # ========================================================

    print_section(
        7,
        "TLS INFORMATION"
    )

    try:

        tls_result = check_tls(
            domain
        )

    except Exception as e:

        tls_result = {

            "version":
                None,

            "cipher":
                None,

            "handshake_time_ms":
                None,

            "certificate":
                {},

            "error":
                str(e)

        }

    print(
        f"TLS Version     : "
        f"{tls_result.get('version', 'N/A')}"
    )

    print(
        f"Cipher          : "
        f"{tls_result.get('cipher', 'N/A')}"
    )

    handshake = tls_result.get(
        "handshake_time_ms"
    )

    if handshake is not None:

        print(
            f"Handshake       : "
            f"{handshake:.2f} ms"
        )

    else:

        print(
            "Handshake       : N/A"
        )

    # ========================================================
    # 8. TLS CERTIFICATE
    # ========================================================

    print_section(
        8,
        "TLS CERTIFICATE"
    )

    certificate = tls_result.get(
        "certificate",
        {}
    )

    subject = certificate.get(
        "subject",
        {}
    )

    issuer = certificate.get(
        "issuer",
        {}
    )

    print(
        f"Subject         : "
        f"{subject.get('commonName', 'N/A')}"
    )

    print(
        f"Issuer          : "
        f"{issuer.get('commonName', 'N/A')}"
    )

    print(
        f"Valid From      : "
        f"{certificate.get('valid_from', 'N/A')}"
    )

    print(
        f"Valid Until     : "
        f"{certificate.get('valid_until', 'N/A')}"
    )

    days_remaining = certificate.get(
        "days_remaining"
    )

    if days_remaining is not None:

        print(
            f"Days Remaining  : "
            f"{days_remaining:.2f}"
        )

    else:

        print(
            "Days Remaining  : N/A"
        )

    if certificate.get("valid"):

        print(
            "Certificate     : VALID"
        )

    else:

        print(
            "Certificate     : INVALID/UNKNOWN"
        )

    report["tls"] = tls_result

    # ========================================================
    # 9. HTTP HEADERS
    # ========================================================

    print_section(
        9,
        "HTTP HEADERS"
    )

    headers = https_result.get(
        "headers",
        {}
    )

    if headers:

        for key, value in headers.items():

            print(
                f"{key:<30}: {value}"
            )

    else:

        print(
            "No headers available."
        )

    # ========================================================
    # 10. SECURITY ANALYSIS
    # ========================================================

    print_section(
        10,
        "SECURITY ANALYSIS"
    )

    try:

        security_result = analyze_security(

            tls_result,

            https_result

        )

    except Exception as e:

        security_result = {

            "findings": [

                {

                    "check":
                        "Security Analyzer",

                    "value":
                        "ERROR",

                    "status":
                        "WARNING",

                    "message":
                        str(e)

                }

            ],

            "summary": {

                "pass": 0,
                "warning": 1,
                "info": 0

            }

        }

    report["security"] = security_result

    # --------------------------------------------------------
    # SECURITY FINDINGS
    # --------------------------------------------------------

    for finding in security_result.get(
        "findings",
        []
    ):

        check = finding.get(
            "check",
            "Unknown"
        )

        value = finding.get(
            "value",
            "N/A"
        )

        status = finding.get(
            "status",
            "INFO"
        )

        print(
            f"{check:<25}: "
            f"{value:<25} "
            f"{status}"
        )

    # --------------------------------------------------------
    # SECURITY SUMMARY
    # --------------------------------------------------------

    security_summary = security_result.get(
        "summary",
        {}
    )

    print()

    print(
        "Security Summary"
    )

    print(
        "-" * 35
    )

    print(
        f"PASS     : "
        f"{security_summary.get('pass', 0)}"
    )

    print(
        f"WARNING  : "
        f"{security_summary.get('warning', 0)}"
    )

    print(
        f"INFO     : "
        f"{security_summary.get('info', 0)}"
    )

    # ========================================================
    # 11. LOCAL NETWORK
    # ========================================================

    print_section(
        11,
        "LOCAL NETWORK"
    )

    try:

        network_result = get_network_info()

    except Exception as e:

        network_result = {

            "hostname":
                "Unknown",

            "local_ip":
                "Unknown",

            "system":
                "Unknown",

            "error":
                str(e)

        }

    print(
        f"Hostname    : "
        f"{network_result.get('hostname', 'Unknown')}"
    )

    print(
        f"Local IP    : "
        f"{network_result.get('local_ip', 'Unknown')}"
    )

    print(
        f"System      : "
        f"{network_result.get('system', 'Unknown')}"
    )

    report["network"] = network_result

    # ========================================================
    # TARGET IP
    # ========================================================

    report["ip"] = target_ip

    # ========================================================
    # SCAN COMPLETED
    # ========================================================

    print()

    print("=" * 60)

    print(
        "                 SCAN COMPLETED"
    )

    print("=" * 60)

    print()

    print("Target:")

    print(
        f"  Domain : {domain}"
    )

    print(
        f"  IPv4   : {target_ip}"
    )

    print()

    print(
        "Network modules:"
    )

    print("  ✓ DNS")
    print("  ✓ DNS Records")
    print("  ✓ DNS Health")
    print("  ✓ IPv4 / IPv6")
    print("  ✓ TCP")
    print("  ✓ Port checking")
    print("  ✓ HTTP")
    print("  ✓ HTTPS")
    print("  ✓ TLS")
    print("  ✓ TLS Certificate")
    print("  ✓ Safe HTTP Headers")
    print("  ✓ Security Analysis")
    print("  ✓ Local Network")

    print()

    print("=" * 60)

    # ========================================================
    # JSON REPORT
    # ========================================================

    if json_mode:

        print()

        print(
            "JSON REPORT"
        )

        print(
            "=" * 60
        )

        print(
            json.dumps(
                report,
                indent=4,
                default=str
            )
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
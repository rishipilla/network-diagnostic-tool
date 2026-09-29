import dns.resolver
import dns.exception


def query_record(domain, record_type):

    try:

        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=5
        )

        return [
            answer.to_text()
            for answer in answers
        ]

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout
    ):

        return []

    except Exception:

        return []


def analyze_dns_health(domain):

    findings = []

    # --------------------------------------------------------
    # A RECORD
    # --------------------------------------------------------

    a_records = query_record(
        domain,
        "A"
    )

    if a_records:

        findings.append({
            "check": "A Record",
            "value": f"{len(a_records)} found",
            "status": "PASS",
            "message": "IPv4 DNS record detected."
        })

    else:

        findings.append({
            "check": "A Record",
            "value": "NOT FOUND",
            "status": "WARNING",
            "message": "No IPv4 DNS record detected."
        })

    # --------------------------------------------------------
    # AAAA RECORD
    # --------------------------------------------------------

    aaaa_records = query_record(
        domain,
        "AAAA"
    )

    if aaaa_records:

        findings.append({
            "check": "AAAA Record",
            "value": f"{len(aaaa_records)} found",
            "status": "PASS",
            "message": "IPv6 DNS record detected."
        })

    else:

        findings.append({
            "check": "AAAA Record",
            "value": "NOT FOUND",
            "status": "INFO",
            "message": "No IPv6 DNS record detected."
        })

    # --------------------------------------------------------
    # MX RECORD
    # --------------------------------------------------------

    mx_records = query_record(
        domain,
        "MX"
    )

    if mx_records:

        findings.append({
            "check": "MX Record",
            "value": f"{len(mx_records)} found",
            "status": "PASS",
            "message": "Mail exchange configuration detected."
        })

    else:

        findings.append({
            "check": "MX Record",
            "value": "NOT FOUND",
            "status": "INFO",
            "message": "No mail server configuration detected."
        })

    # --------------------------------------------------------
    # NS RECORD
    # --------------------------------------------------------

    ns_records = query_record(
        domain,
        "NS"
    )

    if len(ns_records) >= 2:

        findings.append({
            "check": "Nameservers",
            "value": f"{len(ns_records)} found",
            "status": "PASS",
            "message": "Multiple authoritative nameservers detected."
        })

    elif len(ns_records) == 1:

        findings.append({
            "check": "Nameservers",
            "value": "1 found",
            "status": "WARNING",
            "message": "Only one nameserver was detected."
        })

    else:

        findings.append({
            "check": "Nameservers",
            "value": "NOT FOUND",
            "status": "WARNING",
            "message": "No nameserver records detected."
        })

    # --------------------------------------------------------
    # CNAME
    # --------------------------------------------------------

    cname_records = query_record(
        domain,
        "CNAME"
    )

    if cname_records:

        findings.append({
            "check": "CNAME",
            "value": cname_records[0],
            "status": "INFO",
            "message": "Canonical name record detected."
        })

    else:

        findings.append({
            "check": "CNAME",
            "value": "NOT FOUND",
            "status": "INFO",
            "message": "No CNAME record detected at the root."
        })

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    txt_records = query_record(
        domain,
        "TXT"
    )

    spf_records = [
        record
        for record in txt_records
        if "v=spf1" in record.lower()
    ]

    if spf_records:

        findings.append({
            "check": "SPF",
            "value": "DETECTED",
            "status": "PASS",
            "message": "SPF policy detected."
        })

    else:

        findings.append({
            "check": "SPF",
            "value": "NOT DETECTED",
            "status": "WARNING",
            "message": "No SPF policy was detected."
        })

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    dmarc_records = query_record(
        f"_dmarc.{domain}",
        "TXT"
    )

    dmarc_policy = [
        record
        for record in dmarc_records
        if "v=dmarc1" in record.lower()
    ]

    if dmarc_policy:

        findings.append({
            "check": "DMARC",
            "value": "DETECTED",
            "status": "PASS",
            "message": "DMARC policy detected."
        })

    else:

        findings.append({
            "check": "DMARC",
            "value": "NOT DETECTED",
            "status": "WARNING",
            "message": "No DMARC policy was detected."
        })

    # --------------------------------------------------------
    # SOA
    # --------------------------------------------------------

    soa_records = query_record(
        domain,
        "SOA"
    )

    if soa_records:

        findings.append({
            "check": "SOA",
            "value": "PRESENT",
            "status": "PASS",
            "message": "Start of Authority record detected."
        })

    else:

        findings.append({
            "check": "SOA",
            "value": "NOT FOUND",
            "status": "WARNING",
            "message": "SOA record was not detected."
        })

    # --------------------------------------------------------
    # DNSSEC
    # --------------------------------------------------------

    dnskey_records = query_record(
        domain,
        "DNSKEY"
    )

    if dnskey_records:

        findings.append({
            "check": "DNSSEC",
            "value": "DNSKEY DETECTED",
            "status": "PASS",
            "message": "DNSSEC-related DNSKEY records detected."
        })

    else:

        findings.append({
            "check": "DNSSEC",
            "value": "NOT DETECTED",
            "status": "INFO",
            "message": "DNSKEY records were not detected."
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
        "records": {
            "A": a_records,
            "AAAA": aaaa_records,
            "MX": mx_records,
            "NS": ns_records,
            "CNAME": cname_records,
            "TXT": txt_records,
            "DMARC": dmarc_records,
            "SOA": soa_records,
            "DNSKEY": dnskey_records
        },
        "summary": {
            "pass": pass_count,
            "warning": warning_count,
            "info": info_count
        }
    }
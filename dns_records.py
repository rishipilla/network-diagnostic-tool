import dns.resolver


def get_dns_records(domain):
    """
    Retrieve common DNS records.
    """

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT"
    ]

    results = {}

    for record_type in record_types:

        records = []

        try:

            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=5
            )

            for answer in answers:

                records.append(
                    str(answer)
                )

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout
        ):

            pass

        results[record_type] = records

    return results
import socket


def resolve_domain(domain):
    """
    Resolve a domain into IPv4 and IPv6 addresses.
    """

    ipv4_addresses = set()
    ipv6_addresses = set()

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC
        )

        for result in results:

            address_family = result[0]
            address = result[4][0]

            if address_family == socket.AF_INET:
                ipv4_addresses.add(address)

            elif address_family == socket.AF_INET6:
                ipv6_addresses.add(address)

        return {
            "ipv4": sorted(ipv4_addresses),
            "ipv6": sorted(ipv6_addresses)
        }

    except socket.gaierror:

        return {
            "ipv4": [],
            "ipv6": []
        }
import socket
import ssl
import time

from datetime import datetime, timezone


def parse_certificate_name(name):
    """
    Convert certificate subject/issuer tuples
    into a simple dictionary.
    """

    result = {}

    for group in name:

        for key, value in group:

            result[key] = value

    return result


def check_tls(domain):
    """
    Check TLS connection and certificate information.
    """

    try:

        context = ssl.create_default_context()

        start = time.perf_counter()

        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_socket:

                end = time.perf_counter()

                handshake_time = (
                    end - start
                ) * 1000

                cipher = (
                    secure_socket.cipher()
                )

                certificate = (
                    secure_socket.getpeercert()
                )

                # ----------------------------------------
                # TLS information
                # ----------------------------------------

                result = {

                    "version":
                        secure_socket.version(),

                    "cipher":
                        cipher[0]
                        if cipher
                        else None,

                    "handshake_time":
                        handshake_time,

                    "certificate":
                        {}
                }

                # ----------------------------------------
                # Certificate subject
                # ----------------------------------------

                subject = certificate.get(
                    "subject",
                    ()
                )

                subject_values = (
                    parse_certificate_name(
                        subject
                    )
                )

                # ----------------------------------------
                # Certificate issuer
                # ----------------------------------------

                issuer = certificate.get(
                    "issuer",
                    ()
                )

                issuer_values = (
                    parse_certificate_name(
                        issuer
                    )
                )

                # ----------------------------------------
                # Certificate dates
                # ----------------------------------------

                not_before = certificate.get(
                    "notBefore"
                )

                not_after = certificate.get(
                    "notAfter"
                )

                valid_from = None
                valid_until = None
                days_remaining = None

                if not_before:

                    valid_from = (
                        datetime.strptime(
                            not_before,
                            "%b %d %H:%M:%S %Y %Z"
                        ).replace(
                            tzinfo=timezone.utc
                        )
                    )

                if not_after:

                    valid_until = (
                        datetime.strptime(
                            not_after,
                            "%b %d %H:%M:%S %Y %Z"
                        ).replace(
                            tzinfo=timezone.utc
                        )
                    )

                    now = datetime.now(
                        timezone.utc
                    )

                    days_remaining = (
                        valid_until - now
                    ).total_seconds() / 86400

                # ----------------------------------------
                # Certificate status
                # ----------------------------------------

                certificate_valid = (
                    days_remaining is not None
                    and days_remaining > 0
                )

                # ----------------------------------------
                # Store certificate information
                # ----------------------------------------

                result["certificate"] = {

                    "subject":
                        subject_values,

                    "issuer":
                        issuer_values,

                    "valid_from":
                        valid_from.isoformat()
                        if valid_from
                        else None,

                    "valid_until":
                        valid_until.isoformat()
                        if valid_until
                        else None,

                    "days_remaining":
                        round(
                            days_remaining,
                            2
                        )
                        if days_remaining
                        is not None
                        else None,

                    "valid":
                        certificate_valid
                }

                return result

    except Exception as e:

        return {

            "version":
                None,

            "cipher":
                None,

            "handshake_time":
                None,

            "certificate":
                {},

            "error":
                str(e)
        }
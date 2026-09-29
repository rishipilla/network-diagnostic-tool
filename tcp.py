import socket
import time


def check_port(ip, port, timeout=2):
    """
    Check whether a TCP port is reachable.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:

        start = time.perf_counter()

        result = sock.connect_ex(
            (ip, port)
        )

        end = time.perf_counter()

        connection_time = (
            end - start
        ) * 1000

        if result == 0:

            return {
                "status": "OPEN",
                "time": connection_time
            }

        return {
            "status": "CLOSED/FILTERED",
            "time": None
        }

    except socket.error:

        return {
            "status": "ERROR",
            "time": None
        }

    finally:

        sock.close()
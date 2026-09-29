import socket
import platform


def get_network_info():
    """
    Get local computer network information.
    """

    hostname = socket.gethostname()

    try:

        local_ip = socket.gethostbyname(
            hostname
        )

    except socket.error:

        local_ip = "Unknown"

    return {

        "hostname":
            hostname,

        "local_ip":
            local_ip,

        "system":
            platform.system()
    }
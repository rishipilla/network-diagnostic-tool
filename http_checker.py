import urllib.request
import urllib.error
import time


# ============================================================
# SAFE HTTP HEADERS
# ============================================================

SAFE_HEADERS = [
    "Server",
    "Content-Type",
    "Content-Length",
    "Cache-Control",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Content-Security-Policy",
    "Alt-Svc",
    "Content-Encoding",
    "Connection"
]


# ============================================================
# EXTRACT SAFE HEADERS
# ============================================================

def extract_safe_headers(headers):
    """
    Extract selected HTTP response headers.

    Only diagnostic/security-relevant headers are returned.
    Sensitive session/authentication headers are excluded.
    """

    result = {}

    for header in SAFE_HEADERS:

        value = headers.get(header)

        if value is not None:

            result[header] = value

    return result


# ============================================================
# HTTP / HTTPS CHECK
# ============================================================

def check_http(domain, secure=False):
    """
    Check an HTTP or HTTPS endpoint.

    Parameters:
        domain  : Target domain
        secure  : False = HTTP
                  True  = HTTPS

    Returns:
        Dictionary containing:
        - status
        - reason
        - response time
        - safe headers
    """

    protocol = (
        "https"
        if secure
        else "http"
    )

    url = f"{protocol}://{domain}"

    try:

        # ----------------------------------------------------
        # Start timer
        # ----------------------------------------------------

        start = time.perf_counter()


        # ----------------------------------------------------
        # Create request
        # ----------------------------------------------------

        request = urllib.request.Request(

            url,

            headers={
                "User-Agent":
                    "NetworkDiagnosticTool/5.2"
            }

        )


        # ----------------------------------------------------
        # Send request
        # ----------------------------------------------------

        response = urllib.request.urlopen(

            request,

            timeout=5

        )


        # ----------------------------------------------------
        # Stop timer
        # ----------------------------------------------------

        end = time.perf_counter()


        response_time = (
            end - start
        ) * 1000


        # ----------------------------------------------------
        # Extract safe headers
        # ----------------------------------------------------

        headers = extract_safe_headers(
            response.headers
        )


        # ----------------------------------------------------
        # Build result
        # ----------------------------------------------------

        result = {

            "status":
                response.status,

            "reason":
                response.reason,

            "time":
                response_time,

            "headers":
                headers

        }


        # ----------------------------------------------------
        # Close connection
        # ----------------------------------------------------

        response.close()


        return result


    # ========================================================
    # HTTP ERROR
    # ========================================================

    except urllib.error.HTTPError as e:

        return {

            "status":
                e.code,

            "reason":
                e.reason,

            "time":
                None,

            "headers":
                extract_safe_headers(
                    e.headers
                )

        }


    # ========================================================
    # GENERAL ERROR
    # ========================================================

    except Exception as e:

        return {

            "status":
                None,

            "reason":
                str(e),

            "time":
                None,

            "headers":
                {}

        }
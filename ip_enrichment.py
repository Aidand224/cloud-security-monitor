import ipaddress
import requests


def enrich_ip(ip_address):
    """
    Enrich a public IP address with basic geographic/network information.
    Private/reserved/test IPs return simulated-safe information.
    """

    try:
        ip = ipaddress.ip_address(ip_address)

        # Don't send private/reserved/test addresses to an external service.
        if not ip.is_global:
            return {
                "ip_address": ip_address,
                "country": "N/A",
                "region": "N/A",
                "city": "N/A",
                "organization": "Private/Reserved/Test Address",
                "latitude": None,
                "longitude": None,
                "enrichment_status": "LOCAL_OR_RESERVED",
            }

        response = requests.get(
            f"https://ipwho.is/{ip_address}",
            timeout=5
        )

        response.raise_for_status()
        data = response.json()

        if not data.get("success", True):
            raise ValueError(data.get("message", "IP lookup failed"))

        connection = data.get("connection") or {}

        return {
            "ip_address": ip_address,
            "country": data.get("country", "Unknown"),
            "region": data.get("region", "Unknown"),
            "city": data.get("city", "Unknown"),
            "organization": connection.get("org", "Unknown"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "enrichment_status": "SUCCESS",
        }

    except Exception as error:
        return {
            "ip_address": ip_address,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "organization": "Unknown",
            "latitude": None,
            "longitude": None,
            "enrichment_status": "ERROR",
            "error": str(error),
        }


if __name__ == "__main__":
    test_ip = "8.8.8.8"
    result = enrich_ip(test_ip)

    print("\nIP ENRICHMENT TEST")
    print("------------------")

    for key, value in result.items():
        print(f"{key}: {value}")
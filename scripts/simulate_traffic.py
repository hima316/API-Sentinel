"""Standalone API traffic simulator for API Sentinel (Part 6).

Sends simulated client traffic to a configurable API base URL (default: http://127.0.0.1:8000).
Generates distinct behavioral scenarios with explicit ground truth labels:
1. Normal product catalog browsing (Normal, Label: 0)
2. Normal authenticated user activity (Normal, Label: 0)
3. Repeated failed login brute force (Abuse, Label: 1)
4. Rapid request bursts / scraping spikes (Abuse, Label: 1)
5. Endpoint probing / directory scans (Abuse, Label: 1)
6. Mixed suspicious behavior (Abuse, Label: 1)

SECURITY NOTICE:
Requests are dispatched strictly to the target base URL. Traffic is never sent to third-party hosts.

Usage:
    python scripts/simulate_traffic.py [--base-url http://127.0.0.1:8000] [--output reports/simulation_manifest.json]
"""

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("simulate_traffic")


def run_scenario_normal_browsing(
    client: httpx.Client,
    client_id: str = "client-normal-alpha",
    count: int = 15,
    delay: float = 0.05,
) -> Dict[str, Any]:
    """Simulate normal, legitimate user browsing catalog endpoints."""
    logger.info("Executing Scenario: Normal Browsing (Client: %s, Requests: %d)...", client_id, count)
    endpoints = [
        ("GET", "/health"),
        ("GET", "/api/products"),
        ("GET", "/api/products/1"),
        ("GET", "/api/products/2"),
        ("GET", "/api/products/3"),
        ("GET", "/"),
    ]

    status_codes: List[int] = []
    start_time = datetime.now(timezone.utc)

    for i in range(count):
        method, path = endpoints[i % len(endpoints)]
        res = client.request(method, path, headers={"X-Client-ID": client_id})
        status_codes.append(res.status_code)
        if delay > 0:
            time.sleep(delay)

    return {
        "client_id": client_id,
        "scenario": "normal_browsing",
        "ground_truth_label": 0,  # Normal
        "threat_category": "none",
        "requests_sent": len(status_codes),
        "status_distribution": {str(c): status_codes.count(c) for c in set(status_codes)},
        "start_time": start_time.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
    }


def run_scenario_normal_authenticated(
    client: httpx.Client,
    client_id: str = "client-normal-beta",
    count: int = 10,
    delay: float = 0.05,
) -> Dict[str, Any]:
    """Simulate legitimate user logging in successfully and viewing resources."""
    logger.info("Executing Scenario: Normal Authenticated User (Client: %s)...", client_id)
    status_codes: List[int] = []
    start_time = datetime.now(timezone.utc)

    # 1. Successful login
    login_res = client.post(
        "/api/login",
        json={"username": "admin", "password": "sentinel123"},
        headers={"X-Client-ID": client_id},
    )
    status_codes.append(login_res.status_code)
    if delay > 0:
        time.sleep(delay)

    # 2. Subsequent browsing
    for i in range(count - 1):
        res = client.get(
            f"/api/products/{1 + (i % 4)}",
            headers={"X-Client-ID": client_id},
        )
        status_codes.append(res.status_code)
        if delay > 0:
            time.sleep(delay)

    return {
        "client_id": client_id,
        "scenario": "normal_authenticated",
        "ground_truth_label": 0,  # Normal
        "threat_category": "none",
        "requests_sent": len(status_codes),
        "status_distribution": {str(c): status_codes.count(c) for c in set(status_codes)},
        "start_time": start_time.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
    }


def run_scenario_failed_logins(
    client: httpx.Client,
    client_id: str = "client-brute-force",
    count: int = 7,
    delay: float = 0.05,
) -> Dict[str, Any]:
    """Simulate credential brute-force attack with repeated failed logins."""
    logger.info("Executing Scenario: Repeated Failed Logins (Client: %s, Attempts: %d)...", client_id, count)
    status_codes: List[int] = []
    start_time = datetime.now(timezone.utc)

    for i in range(count):
        res = client.post(
            "/api/login",
            json={"username": "admin", "password": f"incorrect-guess-{i}"},
            headers={"X-Client-ID": client_id},
        )
        status_codes.append(res.status_code)
        if delay > 0:
            time.sleep(delay)

    return {
        "client_id": client_id,
        "scenario": "failed_logins_brute_force",
        "ground_truth_label": 1,  # Suspicious / Malicious
        "threat_category": "credential_stuffing",
        "requests_sent": len(status_codes),
        "status_distribution": {str(c): status_codes.count(c) for c in set(status_codes)},
        "start_time": start_time.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
    }


def run_scenario_request_burst(
    client: httpx.Client,
    client_id: str = "client-request-burst",
    count: int = 35,
) -> Dict[str, Any]:
    """Simulate rapid burst of requests (scraping or DoS flood) with no delay."""
    logger.info("Executing Scenario: Request Burst (Client: %s, Requests: %d, no delay)...", client_id, count)
    status_codes: List[int] = []
    start_time = datetime.now(timezone.utc)

    for i in range(count):
        path = "/api/products" if i % 2 == 0 else f"/api/products/{1 + (i % 3)}"
        res = client.get(path, headers={"X-Client-ID": client_id})
        status_codes.append(res.status_code)

    return {
        "client_id": client_id,
        "scenario": "request_burst",
        "ground_truth_label": 1,  # Suspicious / Malicious
        "threat_category": "traffic_burst",
        "requests_sent": len(status_codes),
        "status_distribution": {str(c): status_codes.count(c) for c in set(status_codes)},
        "start_time": start_time.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
    }


def run_scenario_endpoint_probing(
    client: httpx.Client,
    client_id: str = "client-endpoint-probing",
    delay: float = 0.05,
) -> Dict[str, Any]:
    """Simulate directory traversal and vulnerability scanner probing non-existent paths."""
    probe_paths = [
        "/.env",
        "/admin.php",
        "/wp-login.php",
        "/wp-admin",
        "/phpmyadmin",
        "/etc/passwd",
        "/api/v2/secret",
        "/.git/config",
        "/server-status",
        "/backup.sql",
    ]
    logger.info("Executing Scenario: Endpoint Probing (Client: %s, Distinct Paths: %d)...", client_id, len(probe_paths))
    status_codes: List[int] = []
    start_time = datetime.now(timezone.utc)

    for path in probe_paths:
        res = client.get(path, headers={"X-Client-ID": client_id})
        status_codes.append(res.status_code)
        if delay > 0:
            time.sleep(delay)

    return {
        "client_id": client_id,
        "scenario": "endpoint_probing",
        "ground_truth_label": 1,  # Suspicious / Malicious
        "threat_category": "directory_fuzzing",
        "requests_sent": len(status_codes),
        "status_distribution": {str(c): status_codes.count(c) for c in set(status_codes)},
        "start_time": start_time.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
    }


def run_scenario_mixed_abuse(
    client: httpx.Client,
    client_id: str = "client-mixed-abuse",
    delay: float = 0.05,
) -> Dict[str, Any]:
    """Simulate multi-vector behavior: normal browsing mixed with probing and failed logins."""
    logger.info("Executing Scenario: Mixed Abuse Behavior (Client: %s)...", client_id)
    status_codes: List[int] = []
    start_time = datetime.now(timezone.utc)

    # 1. Normal calls
    for path in ["/api/products", "/health", "/api/products/1"]:
        res = client.get(path, headers={"X-Client-ID": client_id})
        status_codes.append(res.status_code)
        if delay > 0:
            time.sleep(delay)

    # 2. Probing calls
    for path in ["/admin/config", "/.env.local", "/secret.key", "/debug/vars"]:
        res = client.get(path, headers={"X-Client-ID": client_id})
        status_codes.append(res.status_code)
        if delay > 0:
            time.sleep(delay)

    # 3. Failed login attempts
    for pwd in ["123456", "admin123", "password"]:
        res = client.post(
            "/api/login",
            json={"username": "admin", "password": pwd},
            headers={"X-Client-ID": client_id},
        )
        status_codes.append(res.status_code)
        if delay > 0:
            time.sleep(delay)

    return {
        "client_id": client_id,
        "scenario": "mixed_abuse",
        "ground_truth_label": 1,  # Suspicious / Malicious
        "threat_category": "multi_vector_abuse",
        "requests_sent": len(status_codes),
        "status_distribution": {str(c): status_codes.count(c) for c in set(status_codes)},
        "start_time": start_time.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
    }


def simulate_all_scenarios(
    base_url: str = "http://127.0.0.1:8000",
    client: Optional[httpx.Client] = None,
    delay: float = 0.03,
) -> Dict[str, Any]:
    """Execute all traffic simulation scenarios against target API and return manifest.

    Args:
        base_url: Base URL of the API server.
        client: Optional pre-configured httpx.Client (e.g., TestClient for testing).
        delay: Intersite request delay in seconds.

    Returns:
        Dictionary containing overall simulation metadata and per-client manifests.
    """
    close_client = False
    if client is None:
        client = httpx.Client(base_url=base_url, timeout=10.0)
        close_client = True

    try:
        # Pre-flight health check
        try:
            health = client.get("/health")
            if health.status_code != 200:
                logger.warning("API health check returned non-200 (%d). Proceeding with caution.", health.status_code)
        except Exception as exc:
            raise ConnectionError(
                f"Could not connect to API at '{base_url}'. Ensure the server is running:\n"
                f"  uvicorn app.main:app --reload\nError details: {exc}"
            ) from exc

        manifests: List[Dict[str, Any]] = []

        # 1. Normal traffic scenarios
        manifests.append(run_scenario_normal_browsing(client, "client-normal-alpha", count=15, delay=delay))
        manifests.append(run_scenario_normal_authenticated(client, "client-normal-beta", count=10, delay=delay))

        # 2. Malicious / abusive scenarios
        manifests.append(run_scenario_failed_logins(client, "client-brute-force", count=7, delay=delay))
        manifests.append(run_scenario_request_burst(client, "client-request-burst", count=35))
        manifests.append(run_scenario_endpoint_probing(client, "client-endpoint-probing", delay=delay))
        manifests.append(run_scenario_mixed_abuse(client, "client-mixed-abuse", delay=delay))

        total_requests = sum(m["requests_sent"] for m in manifests)
        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_base_url": base_url,
            "total_clients": len(manifests),
            "total_requests": total_requests,
            "normal_clients_count": sum(1 for m in manifests if m["ground_truth_label"] == 0),
            "malicious_clients_count": sum(1 for m in manifests if m["ground_truth_label"] == 1),
            "scenarios": manifests,
        }

        return summary
    finally:
        if close_client:
            client.close()


def main() -> None:
    """CLI entrypoint for traffic simulation."""
    parser = argparse.ArgumentParser(description="Simulate API Sentinel traffic scenarios.")
    parser.add_argument(
        "--base-url",
        type=str,
        default="http://127.0.0.1:8000",
        help="Target API base URL (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.03,
        help="Inter-request delay in seconds (default: 0.03)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="reports/simulation_manifest.json",
        help="Path to save simulation manifest (default: reports/simulation_manifest.json)",
    )

    args = parser.parse_args()

    logger.info("Starting traffic simulation against %s...", args.base_url)
    manifest = simulate_all_scenarios(base_url=args.base_url, delay=args.delay)

    out_file = Path(args.output)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info("Simulation completed! Sent %d requests across %d clients.", manifest["total_requests"], manifest["total_clients"])
    logger.info("Saved simulation manifest to %s", out_file)


if __name__ == "__main__":
    main()

import logging
from datetime import datetime, timezone
import json
from ipaddress import ip_address
from pathlib import Path
import re
import time
import urllib.parse
from urllib.request import Request, urlopen

from flask import Flask, jsonify, render_template, request

PROJECT_HONEYPOT_URL = "https://www.projecthoneypot.org/list_of_ips.php"
RESTCOUNTRIES_ALPHA_URL = "https://restcountries.com/v3.1/alpha/"
COUNTRY_SHAPE_BASE_URL = "https://borderly.dev/country"
COUNTRY_FLAG_BASE_URL = "https://borderly.dev/flag"
_honeypot_cache: dict[str, object] = {"ts": 0.0, "index": {}}
_country_cache: dict[str, dict] = {}


def create_app() -> Flask:
    app = Flask(__name__)

    _configure_logging(app)

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            ip_input = str(request.form.get("ip", "")).strip()
            status, log_ip, intel = _ip_status(ip_input)
            now = datetime.now(timezone.utc).isoformat()
            app.logger.info(
                "ip_lookup ip=%s timestamp=%s result=%s", log_ip, now, status
            )
            return render_template(
                "index.html",
                title="IP Reconnaissance",
                ip=ip_input,
                status=status,
                intel=intel,
            )

        return render_template(
            "index.html", title="IP Reconnaissance", ip="", status="", intel=None
        )

    @app.post("/check")
    def check_ip():
        ip_input = _extract_ip_from_request(request)
        now = datetime.now(timezone.utc).isoformat()
        status, log_ip, intel = _ip_status(ip_input)
        app.logger.info("ip_lookup ip=%s timestamp=%s result=%s", log_ip, now, status)
        payload: dict[str, object] = {"status": status}
        if intel:
            payload["intel"] = intel
        return jsonify(payload), 200

    return app


def _configure_logging(app: Flask) -> None:
    log_path = Path(__file__).with_name("logs.txt")

    # Avoid duplicate handlers if the app is reloaded in debug mode.
    if any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "") == str(log_path) for h in app.logger.handlers):
        return

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)


def _extract_ip_from_request(req: request) -> str:
    """
    Accepts either:
    - JSON: { "ip": "1.2.3.4" }
    - Form: ip=1.2.3.4
    """
    data = req.get_json(silent=True) or {}
    ip_value = data.get("ip")
    if ip_value is None:
        ip_value = req.form.get("ip")
    if ip_value is None:
        ip_value = ""
    return str(ip_value).strip()


def _ip_status(ip_input: str) -> tuple[str, str, dict | None]:
    """
    Returns (status, ip_for_logging, intel_if_compromised).
    Status is one of: "Compromised", "Not Compromised", "Invalid IP"
    """
    try:
        parsed = ip_address(ip_input)
        normalized_ip = str(parsed)
    except Exception:
        return "Invalid IP", repr(ip_input), None

    intel_index = _load_blacklist_index()
    intel = intel_index.get(normalized_ip)
    if intel is not None:
        intel = dict(intel)
        intel.setdefault("source", "local_blacklist")
        return "Compromised", normalized_ip, intel

    # Check Project Honey Pot (IPv4 only on that page).
    hp = _honeypot_lookup(normalized_ip)
    if hp is not None:
        return "Compromised", normalized_ip, hp

    return "Not Compromised", normalized_ip, None


def _honeypot_lookup(normalized_ip: str) -> dict | None:
    """
    Looks up an IPv4 in Project Honey Pot's public directory page.
    Returns intel dict like: {"source": "project_honeypot", "country_code": "ua"}

    Uses a simple in-memory cache (TTL) to avoid fetching on every request.
    """
    # Skip if not IPv4-like; the directory page is IPv4.
    if ":" in normalized_ip:
        return None

    index = _honeypot_get_index()
    cc = index.get(normalized_ip)
    if not cc:
        return None
    intel = {"source": "project_honeypot", "country_code": cc.upper()}
    intel["country_shape_url"] = _borderly_country_shape_url(cc.upper())
    intel["country_flag_url"] = _borderly_country_flag_url(cc.upper())
    intel |= _country_map_intel(cc.upper())
    return intel


def _borderly_country_shape_url(country_code: str) -> str:
    # Borderly supports /country/{code}.svg and optional color params.
    code = (country_code or "").strip().lower()
    if not code:
        return ""
    qs = urllib.parse.urlencode(
        {
            "fill": "1d4ed8",  # blue-700
            "stroke": "0b1220",  # dark text
            "strokeWidth": "1.5",
            "bg": "transparent",
            "padding": "6",
            "opacity": "0.9",
        }
    )
    return f"{COUNTRY_SHAPE_BASE_URL}/{code}.svg?{qs}"


def _borderly_country_flag_url(country_code: str) -> str:
    code = (country_code or "").strip().lower()
    if not code:
        return ""
    # Borderly flags are simple; keep background transparent.
    return f"{COUNTRY_FLAG_BASE_URL}/{code}.svg"


def _honeypot_get_index() -> dict[str, str]:
    ttl_seconds = 60 * 60  # 1 hour
    now = time.time()
    cached_ts = float(_honeypot_cache.get("ts", 0.0) or 0.0)
    cached_index = _honeypot_cache.get("index")
    if isinstance(cached_index, dict) and (now - cached_ts) < ttl_seconds:
        return cached_index  # type: ignore[return-value]

    try:
        req = Request(
            PROJECT_HONEYPOT_URL,
            headers={"User-Agent": "recon-app/1.0 (+local dev)"},
        )
        with urlopen(req, timeout=6) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        index = _parse_honeypot_directory_html(html)
    except Exception:
        # If refresh fails, keep whatever we had (even if stale/empty).
        if isinstance(cached_index, dict):
            return cached_index  # type: ignore[return-value]
        index = {}

    _honeypot_cache["ts"] = now
    _honeypot_cache["index"] = index
    return index


def _parse_honeypot_directory_html(html: str) -> dict[str, str]:
    """
    Extracts a map of ip -> country_code from the directory HTML.
    We look for row patterns containing:
      ...ctry=ua)...ip_94.154.35.228...
    """
    index: dict[str, str] = {}
    # Match country code + IPv4 IP in the same vicinity
    pattern = re.compile(
        r"ctry=([a-z]{2}).{0,250}?/ip_((?:\d{1,3}\.){3}\d{1,3})",
        flags=re.IGNORECASE | re.DOTALL,
    )
    for m in pattern.finditer(html):
        cc = m.group(1).lower()
        ip = m.group(2)
        # Basic sanity for octets (avoid weird matches)
        try:
            ip_address(ip)
        except Exception:
            continue
        index[ip] = cc
    return index


def _country_map_intel(country_code: str) -> dict:
    """
    Best-effort: look up country center point (lat/lon) and prepare an OpenStreetMap embed.
    Uses a small in-memory cache keyed by country code.
    """
    code = (country_code or "").strip().upper()
    if not code:
        return {}

    cached = _country_cache.get(code)
    if cached is not None:
        return dict(cached)

    try:
        req = Request(
            f"{RESTCOUNTRIES_ALPHA_URL}{urllib.parse.quote(code)}",
            headers={"User-Agent": "recon-app/1.0 (+local dev)"},
        )
        with urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))

        # API returns a list for /alpha/{code}
        if isinstance(data, list) and data:
            data = data[0]

        latlng = data.get("latlng") if isinstance(data, dict) else None
        name = None
        if isinstance(data, dict):
            name = (data.get("name") or {}).get("common")

        if (
            isinstance(latlng, list)
            and len(latlng) >= 2
            and isinstance(latlng[0], (int, float))
            and isinstance(latlng[1], (int, float))
        ):
            lat = float(latlng[0])
            lon = float(latlng[1])
            embed_url, link_url = _osm_embed_urls(lat, lon)
            result = {
                "country_name": name,
                "map_embed_url": embed_url,
                "map_link_url": link_url,
            }
        else:
            result = {"country_name": name}
    except Exception:
        result = {}

    _country_cache[code] = dict(result)
    return result


def _osm_embed_urls(lat: float, lon: float) -> tuple[str, str]:
    # A simple bbox around the country's center.
    delta = 8.0
    left = max(-180.0, lon - delta)
    right = min(180.0, lon + delta)
    bottom = max(-90.0, lat - delta)
    top = min(90.0, lat + delta)

    qs = urllib.parse.urlencode(
        {
            "bbox": f"{left},{bottom},{right},{top}",
            "layer": "mapnik",
            "marker": f"{lat},{lon}",
        }
    )
    embed_url = f"https://www.openstreetmap.org/export/embed.html?{qs}"
    link_url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=5/{lat}/{lon}"
    return embed_url, link_url


def _load_blacklist_index() -> dict[str, dict]:
    """
    Reads `blacklist.json` and returns a map of normalized IP -> intel record.
    Expected structure:
      { "ips": ["1.2.3.4", ...], ... }
    Or:
      { "ips": [{ "ip": "1.2.3.4", ... }, ...], ... }
    """
    blacklist_path = Path(__file__).with_name("blacklist.json")
    try:
        raw = blacklist_path.read_text(encoding="utf-8")
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}

    ips = payload.get("ips", [])
    if not isinstance(ips, list):
        ips = []

    index: dict[str, dict] = {}
    for item in ips:
        record: dict
        if isinstance(item, dict):
            record = dict(item)
            item = item.get("ip", "")
        else:
            record = {"ip": item}
        try:
            parsed = ip_address(str(item).strip())
            normalized_ip = str(parsed)
        except Exception:
            continue

        record["ip"] = normalized_ip
        index[normalized_ip] = record

    return index


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)


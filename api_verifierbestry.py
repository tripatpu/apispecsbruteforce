#!/usr/bin/env python3
"""
API Endpoint False-Positive Verifier v4.0
==========================================
Two modes:
  1. FFUF MODE (-f):  Parse ffuf JSON output, remove false positives using
                      path intelligence + content analysis + statistical clustering
                      + optional live re-probe.
  2. LIVE MODE (-u -w): Fuzz a target directly with threaded scanning.

Detection layers:
  S1  Path semantic classification (swagger, graphql, openapi, actuator, etc.)
  S2  Content-type validation (json/yaml/xml/protobuf vs text/html)
  S3  Body content fingerprinting (valid JSON? OpenAPI spec? GraphQL schema?
      Prometheus metrics? WSDL? env file? config leak?)
  S4  Path-content correlation scoring
  L1  Content-length frequency clustering
  L2  Word-count / line-count clustering
  L3  SimHash body similarity
  L4  Response-time outlier analysis
  L5  Redirect deduplication
  L6  Body-hash exact duplicate clustering

Usage:
  python api_verifier.py -f ffuf_results.json -o clean.json
  python api_verifier.py -f ffuf_results.json --reprobe -t 50 -o clean.json
  python api_verifier.py -u https://target.com -w wordlist.txt -t 100 -o results.json

License: For authorized penetration testing only.
"""

import argparse
import collections
import hashlib
import json
import math
import os
import re
import signal
import ssl
import statistics
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "4.0.0"
BANNER = r"""
   ___    ____  ____   _    __          _ ____
  / _ |  / __ \/  _/  | |  / /__  ____(_) __/_  __
 / __ | / /_/ // /    | | / / _ \/ __/ / /_/ / / /
/_/ |_|/ .___/___/    | |/ /  __/ /  / / __/ /_/ /
      /_/             |___/\___/_/  /_/_/  \__, /
   False-Positive Verifier  v4.0.0        /____/
"""

RANDOM_SLUGS = [hashlib.md5(os.urandom(8)).hexdigest()[:14] for _ in range(8)]

DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/17.5",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "python-api-verifier/4.0",
]

SOFT_404_KEYWORDS = frozenset({
    "page not found", "not found", "404", "does not exist",
    "cannot be found", "no route", "invalid endpoint", "resource not found",
    "nothing here", "the page you requested", "unavailable",
    "doesn't exist", "could not find", "no such", "error 404",
    "this page doesn't", "oops", "we couldn't find",
})

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.DOTALL)


# ============================================================================
# PATH INTELLIGENCE ENGINE — knows what paths MEAN
# ============================================================================

# Compiled regexes for path classification
_PATH_PATTERNS = {
    # --- API Spec / Documentation ---
    "swagger": re.compile(
        r"(swagger|swagger-ui|swagger-resources|swagger\.json|swagger\.yaml|"
        r"swagger\.yml|swagger-config|swagger/v[0-9]|swagger/api-docs|"
        r"swagger/static|swagger/ui|swagger-ui\.html)", re.I),
    "openapi": re.compile(
        r"(openapi|openapi\.json|openapi\.yaml|openapi\.yml|"
        r"api-docs|api-docs\.json|api-docs\.yaml|api-documentation|"
        r"v[0-9]/api-docs)", re.I),
    "graphql": re.compile(
        r"(graphql|graphiql|playground|gql|voyager|altair|"
        r"graphql-explorer|graphql/console|graphql/schema|"
        r"graphql/introspection|graphql/batch|graphql/subscriptions)", re.I),
    "redoc": re.compile(r"(redoc|rapidoc|scalar|docs$|/docs/$)", re.I),
    "wsdl": re.compile(r"(\?wsdl|\.wsdl|\.xsd|/wsdl$)", re.I),
    "proto": re.compile(r"(\.proto$|/proto$|grpc|grpc/reflection|twirp)", re.I),

    # --- Infrastructure / Debug ---
    "actuator": re.compile(
        r"(actuator|actuator/health|actuator/env|actuator/metrics|"
        r"actuator/mappings|actuator/configprops|actuator/beans|"
        r"actuator/loggers|actuator/httptrace|actuator/info|"
        r"actuator/heapdump|actuator/threaddump|actuator/prometheus|"
        r"actuator/shutdown|actuator/jolokia|actuator/startup)", re.I),
    "metrics": re.compile(
        r"(/metrics$|/prometheus$|/prometheus/|healthz$|readyz$|livez$|"
        r"health-check|healthcheck|_health$|_status$|_ping$|_info$|"
        r"server-status|server-info|build-info)", re.I),
    "debug": re.compile(
        r"(debug|debug/pprof|debug/vars|debug/requests|trace\.axd|"
        r"elmah\.axd|phpinfo|info\.php|__debug__|_debug$|"
        r"web\.config$|WEB-INF|META-INF|console$|jmx-console)", re.I),

    # --- Auth / Identity ---
    "auth": re.compile(
        r"(oauth|oauth2|\.well-known/openid|\.well-known/jwks|"
        r"\.well-known/oauth|connect/token|connect/authorize|"
        r"auth/token|auth/login|auth/callback|iam/|sts/token|"
        r"saml|oidc|identity/connect|/token$|/authorize$)", re.I),

    # --- Config / Secrets Leak ---
    "config_leak": re.compile(
        r"(\.env$|\.git$|\.git/|\.gitignore$|\.htaccess$|\.htpasswd$|"
        r"\.docker|docker-compose|\.aws/credentials|\.ssh/|"
        r"config\.json$|config\.yaml$|config\.yml$|config\.xml$|"
        r"secrets$|configmap|serviceaccount|\.well-known/security\.txt|"
        r"security\.txt$|robots\.txt$|sitemap\.xml$|crossdomain\.xml$)", re.I),

    # --- Cloud Metadata ---
    "cloud_meta": re.compile(
        r"(metadata$|ec2-metadata|computeMetadata|instance/metadata|"
        r"kubernetes|k8s/api|k8s/apis)", re.I),

    # --- Data endpoints (API resources) ---
    "api_json": re.compile(
        r"\.(json|yaml|yml|xml)$", re.I),
}

# Content-type families
_CT_STRUCTURED = re.compile(
    r"(application/json|application/xml|text/xml|application/yaml|"
    r"text/yaml|application/x-yaml|application/x-protobuf|"
    r"application/graphql|application/grpc|application/soap\+xml|"
    r"application/vnd\.|application/hal\+json|application/problem\+json|"
    r"text/csv|text/tab-separated|application/octet-stream)", re.I)

_CT_HTML = re.compile(r"text/html", re.I)


def classify_path(path_or_fuzz):
    """
    Classify a path/fuzz word into semantic categories.
    Returns: (category: str, priority: int)
      priority: 1=critical, 2=high, 3=medium, 4=normal
    """
    p = path_or_fuzz.lower().rstrip("/")

    for cat, regex in _PATH_PATTERNS.items():
        if regex.search(p):
            if cat in ("swagger", "openapi", "graphql", "wsdl", "proto"):
                return cat, 1  # API spec = critical
            if cat in ("config_leak", "cloud_meta"):
                return cat, 1  # secrets = critical
            if cat in ("actuator", "debug"):
                return cat, 2  # infra leak = high
            if cat in ("auth",):
                return cat, 2
            if cat in ("metrics", "redoc"):
                return cat, 2
            if cat == "api_json":
                return cat, 3
            return cat, 3

    return "generic", 4


# ============================================================================
# BODY CONTENT ANALYZER — understands what the response IS
# ============================================================================

class BodyAnalyzer:
    """
    Inspects response body to determine what kind of data was returned.
    Returns structured tags that inform the FP decision.
    """

    # OpenAPI / Swagger spec fingerprints
    _OPENAPI_KEYS = re.compile(
        r'"(openapi|swagger|info|paths|components|definitions|'
        r'basePath|schemes|consumes|produces|securityDefinitions|servers)"', re.I)
    _OPENAPI_YAML = re.compile(
        r'^(openapi|swagger|info|paths|components|definitions|basePath):', re.M | re.I)

    # GraphQL fingerprints
    _GRAPHQL_KEYS = re.compile(
        r'"(__schema|__type|data|query|mutation|subscription|types|queryType)"', re.I)
    _GRAPHQL_SDL = re.compile(
        r'(type\s+Query|type\s+Mutation|schema\s*\{|scalar\s+|interface\s+|enum\s+)', re.I)

    # Prometheus metrics format
    _PROMETHEUS = re.compile(
        r'^# (HELP|TYPE) \w+', re.M)
    _PROMETHEUS_METRIC = re.compile(
        r'^\w+(\{[^}]*\})?\s+[\d.e+-]+', re.M)

    # JSON structure
    _JSON_OBJECT = re.compile(r'^\s*[\{\[]')

    # WSDL / SOAP
    _WSDL = re.compile(r'<(wsdl:definitions|definitions|wsdl:types|xsd:schema)', re.I)
    _SOAP = re.compile(r'<(soap:Envelope|SOAP-ENV:Envelope|wsdl:)', re.I)

    # .env file pattern
    _ENV_FILE = re.compile(r'^[A-Z_][A-Z0-9_]*\s*=\s*.+', re.M)

    # Config / credentials patterns
    _SECRET_PATTERNS = re.compile(
        r'(password|secret|api_key|apikey|api-key|access_token|private_key|'
        r'aws_secret|db_password|database_url|redis_url|mongo_uri|'
        r'jwt_secret|encryption_key|smtp_password)\s*[=:]\s*\S+', re.I)

    # Spring Boot Actuator JSON
    _ACTUATOR = re.compile(
        r'"(status|components|details|diskSpace|db|ping|mail|'
        r'jvm\.memory|system\.cpu|process\.uptime|http\.server)"', re.I)

    # Generic API response
    _API_RESPONSE = re.compile(
        r'"(data|results|items|records|entities|rows|payload|response|'
        r'count|total|page|per_page|pagination|links|meta|errors|error|'
        r'message|code|timestamp|version|id|uuid|created_at|updated_at)"', re.I)

    # HTML page (not API)
    _HTML_FULL = re.compile(
        r'<!DOCTYPE|<html|<head|<body|<div|<script|<link\s+rel=', re.I)

    @classmethod
    def analyze(cls, body, content_type="", path=""):
        """
        Returns: {
          "type": str,          # "openapi_spec", "graphql_schema", "prometheus", etc.
          "is_structured": bool, # True if real data (not generic HTML)
          "is_api_spec": bool,
          "is_config_leak": bool,
          "score": int,          # 0-100 confidence it's real content
          "tags": [str],
          "detail": str,
        }
        """
        result = {
            "type": "unknown",
            "is_structured": False,
            "is_api_spec": False,
            "is_config_leak": False,
            "score": 0,
            "tags": [],
            "detail": "",
        }

        if not body or len(body.strip()) < 2:
            return result

        body_stripped = body.strip()
        ct = (content_type or "").lower()

        # ---- OpenAPI / Swagger spec ----
        openapi_matches = len(cls._OPENAPI_KEYS.findall(body))
        openapi_yaml_matches = len(cls._OPENAPI_YAML.findall(body))
        if openapi_matches >= 3 or openapi_yaml_matches >= 3:
            result["type"] = "openapi_spec"
            result["is_structured"] = True
            result["is_api_spec"] = True
            result["score"] = min(95, 50 + openapi_matches * 10)
            result["tags"].append("openapi")
            result["detail"] = "OpenAPI/Swagger spec (%d key matches)" % max(openapi_matches, openapi_yaml_matches)
            return result

        # ---- GraphQL schema / response ----
        gql_key_matches = len(cls._GRAPHQL_KEYS.findall(body))
        gql_sdl_matches = len(cls._GRAPHQL_SDL.findall(body))
        if gql_key_matches >= 2 or gql_sdl_matches >= 2:
            result["type"] = "graphql_schema"
            result["is_structured"] = True
            result["is_api_spec"] = True
            result["score"] = min(95, 50 + gql_key_matches * 15)
            result["tags"].append("graphql")
            result["detail"] = "GraphQL schema/introspection"
            return result

        # ---- WSDL / SOAP ----
        if cls._WSDL.search(body) or cls._SOAP.search(body):
            result["type"] = "wsdl_soap"
            result["is_structured"] = True
            result["is_api_spec"] = True
            result["score"] = 90
            result["tags"].append("wsdl")
            result["detail"] = "WSDL/SOAP service definition"
            return result

        # ---- Prometheus metrics ----
        prom_help = len(cls._PROMETHEUS.findall(body))
        prom_metric = len(cls._PROMETHEUS_METRIC.findall(body[:4096]))
        if prom_help >= 2 or prom_metric >= 5:
            result["type"] = "prometheus_metrics"
            result["is_structured"] = True
            result["score"] = min(95, 50 + prom_metric * 5)
            result["tags"].append("metrics")
            result["detail"] = "Prometheus metrics (%d metrics)" % prom_metric
            return result

        # ---- .env / config leak ----
        env_matches = len(cls._ENV_FILE.findall(body[:2048]))
        secret_matches = len(cls._SECRET_PATTERNS.findall(body[:4096]))
        if env_matches >= 3 or secret_matches >= 1:
            result["type"] = "config_leak"
            result["is_structured"] = True
            result["is_config_leak"] = True
            result["score"] = min(95, 40 + env_matches * 10 + secret_matches * 20)
            result["tags"].append("config_leak")
            if secret_matches:
                result["tags"].append("secrets_exposed")
            result["detail"] = "Config/env leak (%d env vars, %d secrets)" % (env_matches, secret_matches)
            return result

        # ---- Actuator health/info ----
        actuator_matches = len(cls._ACTUATOR.findall(body))
        if actuator_matches >= 2:
            result["type"] = "actuator"
            result["is_structured"] = True
            result["score"] = min(90, 50 + actuator_matches * 10)
            result["tags"].append("actuator")
            result["detail"] = "Spring Boot Actuator data"
            return result

        # ---- Valid JSON with API keys ----
        if cls._JSON_OBJECT.match(body_stripped):
            try:
                parsed = json.loads(body_stripped[:8192])
                result["is_structured"] = True
                result["tags"].append("valid_json")

                if isinstance(parsed, dict):
                    keys = set(str(k).lower() for k in parsed.keys())
                    api_keys = keys & {
                        "data", "results", "items", "records", "payload",
                        "response", "error", "errors", "message", "code",
                        "status", "count", "total", "page", "per_page",
                        "pagination", "links", "meta", "version", "id",
                    }
                    if api_keys:
                        result["type"] = "api_response"
                        result["score"] = min(85, 30 + len(api_keys) * 12)
                        result["tags"].append("api_response")
                        result["detail"] = "JSON API response (keys: %s)" % ", ".join(sorted(api_keys)[:5])
                        return result

                    # Generic JSON object
                    result["type"] = "json_data"
                    result["score"] = 50 + min(30, len(keys) * 3)
                    result["detail"] = "Valid JSON object (%d keys)" % len(keys)
                    return result

                elif isinstance(parsed, list):
                    result["type"] = "json_array"
                    result["score"] = 50 + min(30, len(parsed) * 2)
                    result["detail"] = "Valid JSON array (%d items)" % len(parsed)
                    return result

            except (json.JSONDecodeError, ValueError):
                pass

        # ---- YAML content (heuristic) ----
        if ("yaml" in ct or "yml" in ct or
                path.endswith((".yaml", ".yml"))) and ":" in body:
            yaml_lines = sum(1 for line in body.split("\n")[:50]
                           if re.match(r'^\s*[\w-]+\s*:', line))
            if yaml_lines >= 3:
                result["type"] = "yaml_data"
                result["is_structured"] = True
                result["score"] = 50 + min(40, yaml_lines * 5)
                result["tags"].append("yaml")
                result["detail"] = "YAML data (%d key lines)" % yaml_lines
                return result

        # ---- XML content ----
        if body_stripped.startswith("<?xml") or body_stripped.startswith("<"):
            xml_tags = len(re.findall(r'<[a-zA-Z][\w:-]*[\s>]', body[:2048]))
            if xml_tags >= 3 and not cls._HTML_FULL.search(body[:1024]):
                result["type"] = "xml_data"
                result["is_structured"] = True
                result["score"] = 40 + min(40, xml_tags * 3)
                result["tags"].append("xml")
                result["detail"] = "XML data (%d tags)" % xml_tags
                return result

        # ---- Generic API response patterns in non-JSON ----
        api_matches = len(cls._API_RESPONSE.findall(body[:2048]))
        if api_matches >= 3:
            result["type"] = "api_like"
            result["is_structured"] = True
            result["score"] = 30 + min(40, api_matches * 8)
            result["tags"].append("api_like")
            result["detail"] = "API-like response (%d field matches)" % api_matches
            return result

        # ---- Full HTML page (likely generic/catch-all) ----
        if cls._HTML_FULL.search(body[:1024]):
            result["type"] = "html_page"
            result["score"] = 10
            result["detail"] = "Generic HTML page"
            return result

        # ---- Plain text ----
        result["type"] = "plain_text"
        result["score"] = 20
        result["detail"] = "Plain text (%d bytes)" % len(body)
        return result


# ============================== SIMHASH =====================================
class SimHash:
    __slots__ = ("value",)

    def __init__(self, data, hashbits=64):
        v = [0] * hashbits
        for t in self._shingle(data):
            h = int(hashlib.md5(t.encode("utf-8", "replace")).hexdigest(), 16)
            for i in range(hashbits):
                v[i] += 1 if h & (1 << i) else -1
        fp = 0
        for i in range(hashbits):
            if v[i] > 0:
                fp |= 1 << i
        self.value = fp

    @staticmethod
    def _shingle(text):
        text = re.sub(r"\s+", " ", text.lower().strip())
        if len(text) < 4:
            return [text] if text else []
        return [text[i:i + 4] for i in range(len(text) - 3)]

    @staticmethod
    def hamming(a, b):
        x = a ^ b
        c = 0
        while x:
            c += 1
            x &= x - 1
        return c


# ============================== DATA ========================================
@dataclass
class FfufEntry:
    url: str
    fuzz_word: str
    input_map: Dict[str, str]
    status: int
    length: int
    words: int
    lines: int
    content_type: str
    redirect_location: str
    duration_ns: int
    host: str
    position: int
    body: str = ""
    simhash: int = 0
    title: str = ""
    is_fp: bool = False
    fp_reason: str = ""
    confidence: str = ""
    body_hash: str = ""
    # New in v4
    path_category: str = ""
    path_priority: int = 4
    content_analysis: str = ""
    content_score: int = 0
    content_tags: str = ""

    @property
    def duration_ms(self):
        return self.duration_ns / 1_000_000

    @property
    def path(self):
        parsed = urllib.parse.urlparse(self.url)
        return parsed.path or "/"


# ============================== FFUF PARSER =================================
def parse_ffuf_json(filepath):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        raw = json.load(f)

    meta = {
        "commandline": raw.get("commandline", ""),
        "time": raw.get("time", ""),
        "total_results": len(raw.get("results", [])),
    }

    entries = []
    for r in raw.get("results", []):
        inp = r.get("input", {})
        if isinstance(inp, dict):
            input_map = {k: str(v) for k, v in inp.items()}
        else:
            input_map = {"FUZZ": str(inp)}

        fuzz_word = input_map.get("FUZZ", "")
        if not fuzz_word and input_map:
            fuzz_word = next(iter(input_map.values()))

        entries.append(FfufEntry(
            url=r.get("url", ""),
            fuzz_word=fuzz_word,
            input_map=input_map,
            status=int(r.get("status", 0)),
            length=int(r.get("length", 0)),
            words=int(r.get("words", 0)),
            lines=int(r.get("lines", 0)),
            content_type=r.get("content-type", r.get("content_type", "")),
            redirect_location=r.get("redirectlocation", ""),
            duration_ns=int(r.get("duration", 0)),
            host=r.get("host", ""),
            position=int(r.get("position", 0)),
        ))

    return entries, meta


# ========================= INTELLIGENT FP ENGINE ============================
class IntelligentFPEngine:
    """
    v4 engine: Path semantics + Content analysis + Statistical clustering.
    """

    def __init__(self, cl_dominance_pct=0.15, word_dominance_pct=0.15,
                 cl_tolerance=10, simhash_threshold=10, min_cluster_size=5,
                 time_zscore=2.5):
        self.cl_dominance_pct = cl_dominance_pct
        self.word_dominance_pct = word_dominance_pct
        self.cl_tolerance = cl_tolerance
        self.simhash_threshold = simhash_threshold
        self.min_cluster_size = min_cluster_size
        self.time_zscore = time_zscore

    def analyze(self, entries):
        if not entries:
            return entries

        total = len(entries)
        log("[*] Analyzing %d ffuf results with intelligent FP detection...\n" % total)

        # =========== PHASE 1: SEMANTIC PATH CLASSIFICATION ============
        log("  [S1] Path semantic classification...")
        cat_counts = collections.Counter()
        for e in entries:
            cat, pri = classify_path(e.fuzz_word or e.path)
            e.path_category = cat
            e.path_priority = pri
            cat_counts[cat] += 1

        for cat, cnt in cat_counts.most_common():
            if cat != "generic":
                label = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "NORMAL"}.get(
                    min(p for e2 in entries if e2.path_category == cat for p in [e2.path_priority]), "?")
                log("       %s: %d paths [%s]" % (cat, cnt, label))
        generic_count = cat_counts.get("generic", 0)
        log("       generic: %d paths" % generic_count)

        # =========== PHASE 2: CONTENT-TYPE ANALYSIS ==================
        log("\n  [S2] Content-type analysis...")
        ct_structured = 0
        ct_html = 0
        ct_other = 0
        for e in entries:
            ct = (e.content_type or "").lower()
            if _CT_STRUCTURED.search(ct):
                ct_structured += 1
            elif _CT_HTML.search(ct):
                ct_html += 1
            else:
                ct_other += 1
        log("       Structured (json/xml/yaml): %d" % ct_structured)
        log("       HTML: %d" % ct_html)
        log("       Other: %d" % ct_other)

        # =========== PHASE 3: BODY CONTENT ANALYSIS (if available) ===
        body_analyzed = 0
        if any(e.body for e in entries):
            log("\n  [S3] Body content fingerprinting...")
            type_counts = collections.Counter()
            for e in entries:
                if e.body:
                    analysis = BodyAnalyzer.analyze(e.body, e.content_type, e.fuzz_word)
                    e.content_analysis = analysis["detail"]
                    e.content_score = analysis["score"]
                    e.content_tags = "; ".join(analysis["tags"]) if analysis["tags"] else ""
                    type_counts[analysis["type"]] += 1
                    body_analyzed += 1
            for btype, cnt in type_counts.most_common():
                log("       %s: %d" % (btype, cnt))
            log("       Bodies analyzed: %d" % body_analyzed)

        # =========== PHASE 4: STATISTICAL CLUSTERING =================
        log("\n  [L1-L6] Statistical clustering...")

        # L1: CL clustering
        cl_counter = collections.Counter(e.length for e in entries)
        dominant_cls = set()
        for cl, count in cl_counter.most_common():
            if count / total >= self.cl_dominance_pct:
                dominant_cls.add(cl)
            elif count >= self.min_cluster_size:
                for dcl in list(dominant_cls):
                    if abs(cl - dcl) <= self.cl_tolerance:
                        dominant_cls.add(cl)
                        break

        if dominant_cls:
            for cl in sorted(dominant_cls):
                cnt = cl_counter[cl]
                log("       [L1] Dominant CL=%d (%dx, %.1f%%)" % (cl, cnt, cnt / total * 100))

        # L2: Word-count
        wc_counter = collections.Counter(e.words for e in entries)
        dominant_wcs = set()
        for wc, count in wc_counter.most_common():
            if count / total >= self.word_dominance_pct:
                dominant_wcs.add(wc)

        # L3: Line-count
        lc_counter = collections.Counter(e.lines for e in entries)
        dominant_lcs = set()
        for lc, count in lc_counter.most_common():
            if count / total >= self.word_dominance_pct:
                dominant_lcs.add(lc)

        # L4: Response time
        times = [e.duration_ms for e in entries if e.duration_ms > 0]
        time_mean = statistics.mean(times) if times else 0
        time_stdev = statistics.stdev(times) if len(times) > 2 else 0

        # L5: Redirect clustering
        redir_counter = collections.Counter(
            e.redirect_location for e in entries if e.redirect_location)
        dominant_redirs = set()
        for loc, count in redir_counter.most_common():
            if count >= self.min_cluster_size:
                dominant_redirs.add(loc)

        # L6: SimHash clustering
        body_simhashes = [(i, e.simhash) for i, e in enumerate(entries) if e.simhash]
        simhash_fp_indices = set()
        if body_simhashes:
            sh_counter = collections.Counter(sh for _, sh in body_simhashes)
            dominant_sh_val, dominant_sh_count = sh_counter.most_common(1)[0]
            if dominant_sh_count / total >= 0.1:
                for idx, sh in body_simhashes:
                    if SimHash.hamming(sh, dominant_sh_val) <= self.simhash_threshold:
                        simhash_fp_indices.add(idx)

        # Body-hash clustering
        bh_counter = collections.Counter(e.body_hash for e in entries if e.body_hash)
        dominant_body_hashes = set()
        for bh, count in bh_counter.most_common():
            if count / total >= self.cl_dominance_pct and count >= self.min_cluster_size:
                dominant_body_hashes.add(bh)

        # =========== PHASE 5: INTELLIGENT CLASSIFICATION =============
        log("\n[*] Intelligent classification (path + content + stats)...")
        fp_count = 0
        reasons_counter = collections.Counter()

        for i, e in enumerate(entries):
            reasons = []
            protections = []

            # --- Statistical signals ---
            cl_match = False
            for dcl in dominant_cls:
                if abs(e.length - dcl) <= self.cl_tolerance:
                    cl_match = True
                    break
            if cl_match:
                reasons.append("cl_cluster")
            if e.words in dominant_wcs:
                reasons.append("wc_cluster")
            if e.lines in dominant_lcs:
                reasons.append("lc_cluster")
            if e.redirect_location and e.redirect_location in dominant_redirs:
                reasons.append("redir_cluster")
            if i in simhash_fp_indices:
                reasons.append("simhash_cluster")
            if e.body_hash and e.body_hash in dominant_body_hashes:
                reasons.append("body_hash_cluster")

            # Soft-404 in title/body
            if e.title:
                for kw in SOFT_404_KEYWORDS:
                    if kw in e.title.lower():
                        reasons.append("soft404_title")
                        break
            if e.body:
                for kw in SOFT_404_KEYWORDS:
                    if kw in e.body[:2048].lower():
                        reasons.append("soft404_body")
                        break

            # --- PATH-BASED PROTECTION ---
            # High-value paths get protected from statistical FP dismissal
            if e.path_priority <= 2:
                protections.append("high_value_path:%s" % e.path_category)

            # --- CONTENT-TYPE PROTECTION ---
            ct = (e.content_type or "").lower()
            if _CT_STRUCTURED.search(ct):
                protections.append("structured_ct:%s" % ct.split(";")[0].strip())

            # --- CONTENT SCORE PROTECTION ---
            if e.content_score >= 50:
                protections.append("content_score:%d" % e.content_score)

            # --- BODY CONTENT PROTECTION ---
            # If body analysis found real API spec/data, protect it
            if e.content_tags:
                tags = e.content_tags.lower()
                if any(t in tags for t in ["openapi", "graphql", "wsdl", "metrics",
                                            "actuator", "config_leak", "secrets_exposed",
                                            "api_response", "valid_json", "yaml"]):
                    protections.append("body_content:%s" % e.content_tags.split(";")[0].strip())

            # --- PATH-CONTENT CORRELATION ---
            # swagger path + json content-type = strong signal
            if e.path_category == "swagger" and ("json" in ct or "yaml" in ct or "xml" in ct):
                protections.append("path_ct_correlation:swagger+structured")
            if e.path_category == "graphql" and "json" in ct:
                protections.append("path_ct_correlation:graphql+json")
            if e.path_category == "metrics" and ("json" in ct or "text/plain" in ct):
                protections.append("path_ct_correlation:metrics+data")
            if e.path_category == "actuator" and "json" in ct:
                protections.append("path_ct_correlation:actuator+json")
            if e.path_category == "api_json" and _CT_STRUCTURED.search(ct):
                protections.append("path_ct_correlation:api_file+structured")

            # --- DECISION ---
            stat_signals = len(reasons)
            protection_signals = len(protections)

            is_fp = False

            # Strong statistical FP signal
            if stat_signals >= 2:
                is_fp = True
            elif stat_signals == 1:
                r = reasons[0]
                if r == "cl_cluster":
                    for dcl in dominant_cls:
                        if abs(e.length - dcl) <= self.cl_tolerance:
                            if cl_counter.get(dcl, 0) / total >= 0.50:
                                is_fp = True
                            break
                elif r in ("body_hash_cluster", "simhash_cluster"):
                    is_fp = True

            # --- PROTECTION OVERRIDES ---
            if is_fp and protection_signals > 0:
                # Critical path (swagger, openapi, graphql, config leak) = always keep
                if e.path_priority == 1:
                    is_fp = False
                    reasons.append("PROTECTED:critical_path")

                # High-value path + structured content-type = keep
                elif e.path_priority == 2 and any("structured_ct" in p for p in protections):
                    is_fp = False
                    reasons.append("PROTECTED:high_path+structured_ct")

                # Any path + real body content (openapi spec, valid json API, etc.)
                elif any("body_content" in p for p in protections):
                    is_fp = False
                    reasons.append("PROTECTED:verified_body_content")

                # Path-content correlation match
                elif any("path_ct_correlation" in p for p in protections):
                    is_fp = False
                    reasons.append("PROTECTED:path_content_match")

                # High content score alone
                elif e.content_score >= 70:
                    is_fp = False
                    reasons.append("PROTECTED:high_content_score_%d" % e.content_score)

            # Status code protection (401/403/405 = endpoint exists)
            if is_fp and e.status in (401, 403, 405):
                status_count = sum(1 for x in entries if x.status == e.status)
                if status_count / total < 0.3:
                    is_fp = False
                    reasons.append("PROTECTED:auth_status")

            # Response time outlier
            if is_fp and time_stdev > 0 and e.duration_ms > 0:
                zscore = (e.duration_ms - time_mean) / time_stdev
                if zscore > self.time_zscore:
                    is_fp = False
                    reasons.append("PROTECTED:time_outlier_z=%.1f" % zscore)

            e.is_fp = is_fp
            e.fp_reason = "; ".join(reasons) if reasons else "unique"
            e.confidence = self._rate_confidence(e, cl_counter, total)

            if is_fp:
                fp_count += 1
                for r in reasons:
                    if not r.startswith("PROTECTED"):
                        reasons_counter[r] += 1

        # Summary
        verified = [e for e in entries if not e.is_fp]
        log("\n[*] Classification complete:")
        log("    Total:           %d" % total)
        log("    False positives: %d" % fp_count)
        log("    Verified hits:   %d" % len(verified))

        if reasons_counter:
            log("    FP breakdown:")
            for reason, cnt in reasons_counter.most_common():
                log("      %s: %d" % (reason, cnt))

        # Categorized summary of verified hits
        if verified:
            log("\n    Verified by category:")
            vcat = collections.Counter(e.path_category for e in verified)
            for cat, cnt in vcat.most_common():
                log("      %s: %d" % (cat, cnt))

        return entries

    def _rate_confidence(self, e, cl_counter, total):
        if e.is_fp:
            return "FP"

        score = 0

        # Path priority
        if e.path_priority == 1:
            score += 40
        elif e.path_priority == 2:
            score += 30
        elif e.path_priority == 3:
            score += 15

        # Status code
        if e.status in (401, 403):
            score += 25
        elif e.status == 405:
            score += 25
        elif e.status in (200, 201):
            score += 10
        elif e.status in (301, 302, 307, 308):
            score += 5

        # Content type
        ct = (e.content_type or "").lower()
        if _CT_STRUCTURED.search(ct):
            score += 20
        elif _CT_HTML.search(ct):
            score += 0  # neutral

        # Content score (from body analysis)
        if e.content_score >= 70:
            score += 25
        elif e.content_score >= 40:
            score += 10

        # CL uniqueness
        cl_freq = cl_counter.get(e.length, 0)
        if cl_freq <= 2:
            score += 15
        elif cl_freq / total < 0.05:
            score += 5

        if score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"


# ========================= HTTP ENGINE ======================================
class HTTPEngine:
    def __init__(self, threads, timeout, proxy, headers, cookies, verify_ssl):
        self.timeout = timeout
        self.headers = headers
        self._ua_idx = 0
        self._lock = threading.Lock()

        if HAS_REQUESTS:
            self.session = requests.Session()
            retry = Retry(total=2, backoff_factor=0.2, status_forcelist=[502, 503, 504])
            adapter = HTTPAdapter(
                max_retries=retry,
                pool_connections=min(threads, 100),
                pool_maxsize=threads,
            )
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)
            self.session.verify = verify_ssl
            if proxy:
                self.session.proxies = {"http": proxy, "https": proxy}
            if cookies:
                for pair in cookies.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        self.session.cookies.set(k.strip(), v.strip())
        else:
            self.session = None
            if not verify_ssl:
                ssl._create_default_https_context = ssl._create_unverified_context

    def _next_ua(self):
        with self._lock:
            ua = DEFAULT_UAS[self._ua_idx % len(DEFAULT_UAS)]
            self._ua_idx += 1
            return ua

    def get(self, url):
        merged = dict(self.headers)
        merged["User-Agent"] = self._next_ua()
        t0 = time.perf_counter()
        try:
            if HAS_REQUESTS and self.session:
                r = self.session.get(url, headers=merged, timeout=self.timeout,
                                     allow_redirects=False, stream=False)
                elapsed = (time.perf_counter() - t0) * 1000
                return {
                    "status": r.status_code, "length": len(r.content),
                    "body": r.text[:16384], "time_ms": round(elapsed, 1),
                    "headers": dict(r.headers),
                    "redirect": r.headers.get("Location", ""),
                    "error": None,
                }
            else:
                import urllib.request
                req = urllib.request.Request(url, headers=merged)
                resp = urllib.request.urlopen(req, timeout=self.timeout)
                body = resp.read(16384).decode("utf-8", "replace")
                elapsed = (time.perf_counter() - t0) * 1000
                return {
                    "status": resp.status, "length": len(body),
                    "body": body, "time_ms": round(elapsed, 1),
                    "headers": dict(resp.headers),
                    "redirect": "", "error": None,
                }
        except Exception as ex:
            return {
                "status": 0, "length": 0, "body": "", "headers": {},
                "time_ms": round((time.perf_counter() - t0) * 1000, 1),
                "redirect": "", "error": str(ex)[:120],
            }


# ========================= RE-PROBE ========================================
def reprobe_entries(entries, http, threads, rate=0):
    log("\n[*] Re-probing %d URLs with %d threads..." % (len(entries), threads))
    delay = 1.0 / rate if rate > 0 else 0
    lock = threading.Lock()
    done = [0]
    total = len(entries)

    def probe_one(entry):
        if delay:
            time.sleep(delay)
        resp = http.get(entry.url)
        if resp["error"]:
            return
        body = resp["body"]
        entry.body = body
        if body:
            entry.simhash = SimHash(body).value
            entry.body_hash = hashlib.md5(body.encode("utf-8", "replace")).hexdigest()[:16]
            m = _TITLE_RE.search(body)
            if m:
                entry.title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            # Update content-type from actual response if ffuf didn't capture it well
            ct = resp["headers"].get("Content-Type", resp["headers"].get("content-type", ""))
            if ct and not entry.content_type:
                entry.content_type = ct
        with lock:
            done[0] += 1
            if done[0] % 200 == 0:
                log("  [reprobe] %d/%d (%.1f%%)" % (done[0], total, done[0] / total * 100))

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(probe_one, e) for e in entries]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception:
                pass

    probed = sum(1 for e in entries if e.body)
    log("  [reprobe] Done. Bodies collected: %d/%d" % (probed, total))
    return entries


# ========================= BASELINE ========================================
def learn_baseline(base_url, http):
    log("[*] Learning target baseline...")
    statuses = set()
    cls = set()
    shs = []
    for slug in RANDOM_SLUGS:
        resp = http.get(base_url + "/" + slug)
        if resp["error"]:
            continue
        statuses.add(resp["status"])
        cls.add(resp["length"])
        if resp["body"]:
            shs.append(SimHash(resp["body"]).value)
    log("    Baseline: statuses=%s, CLs=%s, simhashes=%d" % (statuses, cls, len(shs)))
    return statuses, cls, shs


# ========================= OUTPUT ==========================================
def write_results(entries, filepath, include_fp=False):
    if include_fp:
        out = entries
    else:
        out = [e for e in entries if not e.is_fp]

    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".json":
        data = []
        for e in out:
            row = {
                "url": e.url,
                "path": e.path,
                "fuzz": e.fuzz_word,
                "status": e.status,
                "length": e.length,
                "words": e.words,
                "lines": e.lines,
                "content_type": e.content_type,
                "redirect": e.redirect_location,
                "duration_ms": round(e.duration_ms, 1),
                "host": e.host,
                "confidence": e.confidence,
                "path_category": e.path_category,
                "path_priority": e.path_priority,
                "fp_reason": e.fp_reason,
            }
            if include_fp:
                row["is_false_positive"] = e.is_fp
            if e.title:
                row["title"] = e.title
            if e.body_hash:
                row["body_hash"] = e.body_hash
            if e.content_analysis:
                row["content_analysis"] = e.content_analysis
            if e.content_score:
                row["content_score"] = e.content_score
            if e.content_tags:
                row["content_tags"] = e.content_tags
            if len(e.input_map) > 1:
                row["inputs"] = e.input_map
            data.append(row)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    elif ext == ".csv":
        with open(filepath, "w") as f:
            f.write("url,path,fuzz,status,length,words,lines,content_type,confidence,"
                    "path_category,path_priority,content_score,content_analysis,"
                    "duration_ms,redirect,title,body_hash,is_fp,fp_reason\n")
            for e in out:
                title_esc = e.title.replace('"', '""')
                reason_esc = e.fp_reason.replace('"', '""')
                analysis_esc = e.content_analysis.replace('"', '""')
                f.write('"%s","%s","%s",%d,%d,%d,%d,"%s",%s,"%s",%d,%d,"%s",%.1f,"%s","%s",%s,%s,"%s"\n' % (
                    e.url, e.path, e.fuzz_word, e.status, e.length,
                    e.words, e.lines, e.content_type, e.confidence,
                    e.path_category, e.path_priority, e.content_score,
                    analysis_esc, e.duration_ms, e.redirect_location,
                    title_esc, e.body_hash, e.is_fp, reason_esc))

    elif ext in (".txt", ""):
        with open(filepath, "w") as f:
            for e in out:
                f.write(e.url + "\n")

    else:
        filepath = filepath + ".json"
        write_results(entries, filepath, include_fp)
        return

    verified = sum(1 for e in out if not e.is_fp)
    log("\n[+] Saved %d verified hits to %s" % (verified, filepath))


def _status_color(code):
    if 200 <= code < 300:
        return "\033[92m"
    if 300 <= code < 400:
        return "\033[93m"
    if code in (401, 403):
        return "\033[91m"
    if code == 405:
        return "\033[95m"
    return "\033[96m"

_PRIORITY_COLOR = {
    1: "\033[91m",   # red = critical
    2: "\033[93m",   # yellow = high
    3: "\033[96m",   # cyan = medium
    4: "\033[0m",    # default
}

def print_hit_table(entries):
    verified = [e for e in entries if not e.is_fp]
    if not verified:
        log("[*] No verified endpoints found after filtering.")
        return

    rst = "\033[0m"
    log("\n" + "=" * 120)
    log(" VERIFIED ENDPOINTS (%d hits)" % len(verified))
    log("=" * 120)
    log("%-8s %-10s %-8s %-8s %-10s %-6s %-12s %-6s %s" % (
        "Status", "Length", "Words", "Lines", "Time(ms)", "Conf", "Category", "Score", "URL"))
    log("%-8s %-10s %-8s %-8s %-10s %-6s %-12s %-6s %s" % (
        "-" * 6, "-" * 8, "-" * 6, "-" * 6, "-" * 8, "-" * 5, "-" * 11, "-" * 5, "-" * 40))

    # Sort: priority first, then confidence, then status
    for e in sorted(verified, key=lambda x: (x.path_priority, x.confidence != "HIGH", x.status, x.path)):
        sc = _status_color(e.status)
        pc = _PRIORITY_COLOR.get(e.path_priority, rst)
        redir = " -> " + e.redirect_location if e.redirect_location else ""
        title = '  "%s"' % e.title if e.title else ""
        analysis = '  [%s]' % e.content_analysis if e.content_analysis else ""
        score_str = str(e.content_score) if e.content_score else "-"
        print("%s%-8d%s %-10d %-8d %-8d %-10.0f %-6s %s%-12s%s %-6s %s%s%s%s" % (
            sc, e.status, rst, e.length, e.words, e.lines,
            e.duration_ms, e.confidence,
            pc, e.path_category[:11], rst,
            score_str,
            e.url, redir, title, analysis), flush=True)


# ========================= LIVE SCAN =======================================
def stream_wordlist(filepath):
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield line if line.startswith("/") else ("/" + line)


def count_lines(filepath):
    c = 0
    with open(filepath, "rb") as f:
        while True:
            block = f.read(65536)
            if not block:
                break
            c += block.count(b"\n")
    return c


class LiveScanner:
    def __init__(self, args):
        self.base_url = args.url.rstrip("/")
        self.wordlist = args.wordlist
        self.threads = args.threads
        self.output = args.output
        self.deep = args.deep
        self.quiet = args.quiet

        hdrs = {}
        if args.headers:
            for h in args.headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    hdrs[k.strip()] = v.strip()

        self.http = HTTPEngine(
            threads=self.threads, timeout=args.timeout,
            proxy=args.proxy or "", headers=hdrs,
            cookies=args.cookies or "",
            verify_ssl=not args.no_verify,
        )

        self.match_codes = None
        self.filter_codes = None
        if args.mc:
            self.match_codes = set(int(c) for c in args.mc.split(","))
        if args.fc:
            self.filter_codes = set(int(c) for c in args.fc.split(","))

        self.hits = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._done = 0
        self._errors = 0
        self._fps = 0

    def run(self):
        if not self.quiet:
            log(BANNER)

        total = count_lines(self.wordlist)
        log("[*] Wordlist: %d paths | Threads: %d | Target: %s" % (total, self.threads, self.base_url))

        bl_statuses, bl_cls, bl_shs = learn_baseline(self.base_url, self.http)

        signal.signal(signal.SIGINT, lambda s, f: self._stop.set())
        t0 = time.perf_counter()
        log("[*] Scanning started at %s\n" % time.strftime("%H:%M:%S"))

        BATCH = self.threads * 4
        path_gen = stream_wordlist(self.wordlist)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {}
            finished = False

            while not self._stop.is_set():
                while len(futures) < BATCH and not finished:
                    try:
                        path = next(path_gen)
                        f = pool.submit(self._probe_one, path, bl_statuses, bl_cls, bl_shs)
                        futures[f] = path
                    except StopIteration:
                        finished = True
                        break
                if not futures:
                    break

                done_list = [f for f in futures if f.done()]
                if not done_list:
                    time.sleep(0.01)
                    continue

                for f in done_list:
                    futures.pop(f)
                    self._done += 1
                    try:
                        hit = f.result()
                        if hit is not None:
                            with self._lock:
                                self.hits.append(hit)
                            self._print_live_hit(hit)
                    except Exception:
                        pass

                    if not self.quiet and self._done % 500 == 0:
                        elapsed = time.perf_counter() - t0
                        rps = self._done / elapsed if elapsed else 0
                        log("\r[*] %d/%d (%.1f%%) | %.0f req/s | Hits: %d | FPs: %d | Errs: %d" % (
                            self._done, total, self._done / total * 100,
                            rps, len(self.hits), self._fps, self._errors))

        elapsed = time.perf_counter() - t0
        log("\n" + "=" * 70)
        log("[+] Done in %.1fs | %d requests | %d hits | %d FPs caught" % (
            elapsed, self._done, len(self.hits), self._fps))

        if self.output and self.hits:
            write_results(self.hits, self.output)

    def _probe_one(self, path, bl_statuses, bl_cls, bl_shs):
        if self._stop.is_set():
            return None
        url = self.base_url + path
        resp = self.http.get(url)

        if resp["error"]:
            self._errors += 1
            return None

        st = resp["status"]
        if self.match_codes and st not in self.match_codes:
            return None
        if self.filter_codes and st in self.filter_codes:
            return None

        if st in (404, 410, 501):
            self._fps += 1
            return None

        body = resp["body"]
        length = resp["length"]
        ct = resp["headers"].get("Content-Type", "")

        # Path intelligence
        cat, pri = classify_path(path)

        # Content analysis
        analysis = BodyAnalyzer.analyze(body, ct, path) if body else {
            "type": "unknown", "score": 0, "tags": [], "detail": "",
            "is_structured": False, "is_api_spec": False, "is_config_leak": False,
        }

        # Critical/high-value path with structured content = always keep
        if pri <= 2 and (analysis["is_structured"] or _CT_STRUCTURED.search(ct)):
            pass  # skip FP checks
        elif pri == 1:
            pass  # critical path always kept
        else:
            # Standard FP checks for generic paths
            if st in bl_statuses and st not in (200, 201, 301, 302, 307, 308, 401, 403, 405):
                self._fps += 1
                return None

            for bcl in bl_cls:
                if abs(length - bcl) <= 15:
                    if body and bl_shs:
                        sh = SimHash(body)
                        for bsh in bl_shs:
                            if SimHash.hamming(sh.value, bsh) <= 10:
                                # But protect if body has real content
                                if analysis["score"] < 50:
                                    self._fps += 1
                                    return None
                    elif not body:
                        self._fps += 1
                        return None
                    break

            if body and bl_shs and analysis["score"] < 50:
                sh = SimHash(body)
                for bsh in bl_shs:
                    if SimHash.hamming(sh.value, bsh) <= 8:
                        self._fps += 1
                        return None

        title = ""
        if body:
            m = _TITLE_RE.search(body)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]

        bh = hashlib.md5(body.encode("utf-8", "replace")).hexdigest()[:16] if body else ""
        sh_val = SimHash(body).value if body else 0

        # Confidence based on path + content
        score = 0
        if pri <= 2:
            score += 35
        if st in (401, 403, 405):
            score += 25
        elif st in (200, 201) and length > 50:
            score += 10
        if _CT_STRUCTURED.search(ct):
            score += 20
        if analysis["score"] >= 50:
            score += 20
        conf = "HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "LOW")

        return FfufEntry(
            url=url, fuzz_word=path, input_map={"FUZZ": path},
            status=st, length=length, words=0, lines=0,
            content_type=ct,
            redirect_location=resp["redirect"],
            duration_ns=int(resp["time_ms"] * 1_000_000),
            host="", position=0, body=body[:1024], simhash=sh_val,
            title=title, confidence=conf, body_hash=bh,
            path_category=cat, path_priority=pri,
            content_analysis=analysis["detail"],
            content_score=analysis["score"],
            content_tags="; ".join(analysis["tags"]),
        )

    def _print_live_hit(self, e):
        sc = _status_color(e.status)
        rst = "\033[0m"
        pc = _PRIORITY_COLOR.get(e.path_priority, rst)
        redir = " -> " + e.redirect_location if e.redirect_location else ""
        title = ' "%s"' % e.title if e.title else ""
        analysis = " [%s]" % e.content_analysis if e.content_analysis else ""
        print("%s[%d]%s  CL:%-8d %7.0fms  [%s] %s%-10s%s  %s%s%s%s" % (
            sc, e.status, rst, e.length, e.duration_ms,
            e.confidence, pc, e.path_category[:10], rst,
            e.fuzz_word, redir, title, analysis), flush=True)


# ========================= LOGGING ==========================================
def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


# ========================= CLI ==============================================
def build_parser():
    p = argparse.ArgumentParser(
        description="API False-Positive Verifier v4 -- intelligent path + content analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
FFUF MODE (parse existing results):
  %(prog)s -f ffuf_output.json -o clean.json
  %(prog)s -f ffuf_output.json --reprobe -t 50 -o clean.json
  %(prog)s -f ffuf_output.json --reprobe --proxy http://127.0.0.1:8080 -o clean.json
  %(prog)s -f ffuf_output.json --include-fp -o full_audit.csv

LIVE MODE (direct scanning):
  %(prog)s -u https://target.com -w wordlist.txt -t 100 -o results.json
  %(prog)s -u https://target.com -w wordlist.txt --deep --mc 200,301,401,403,405

TUNING:
  --cl-pct 0.15       Flag CL as dominant if it covers >=15%% of results
  --wc-pct 0.15       Same for word-count
  --cl-tol 10         CL tolerance window (+/- bytes)
  --simhash-threshold 10  SimHash hamming distance to call "similar"
  --min-cluster 5     Minimum cluster size to flag as FP pattern
        """,
    )

    g_mode = p.add_argument_group("Mode selection (pick one)")
    g_mode.add_argument("-f", "--ffuf-file", help="Path to ffuf JSON output file")
    g_mode.add_argument("-u", "--url", help="Target base URL (live mode)")
    g_mode.add_argument("-w", "--wordlist", help="Wordlist file (live mode)")

    g_out = p.add_argument_group("Output")
    g_out.add_argument("-o", "--output", help="Output file (.json, .csv, .txt)")
    g_out.add_argument("--include-fp", action="store_true",
                       help="Include false positives in output (tagged)")

    g_net = p.add_argument_group("Network")
    g_net.add_argument("-t", "--threads", type=int, default=50, help="Threads (default: 50)")
    g_net.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout (default: 10s)")
    g_net.add_argument("-H", "--headers", action="append", help="Custom header: -H 'Key: Value'")
    g_net.add_argument("--cookies", help="Cookies: 'k1=v1; k2=v2'")
    g_net.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    g_net.add_argument("--no-verify", action="store_true", help="Skip SSL verification")
    g_net.add_argument("--rate", type=float, default=0, help="Max req/sec for reprobe (0=unlimited)")

    g_filter = p.add_argument_group("Filtering (live mode)")
    g_filter.add_argument("--mc", help="Match status codes (e.g. 200,301,401)")
    g_filter.add_argument("--fc", help="Filter status codes (e.g. 404,500)")
    g_filter.add_argument("--follow-redirects", action="store_true")
    g_filter.add_argument("--deep", action="store_true", help="Double-probe to confirm hits")

    g_tune = p.add_argument_group("FP tuning")
    g_tune.add_argument("--cl-pct", type=float, default=0.15,
                        help="CL dominance threshold (default: 0.15)")
    g_tune.add_argument("--wc-pct", type=float, default=0.15,
                        help="Word-count dominance threshold (default: 0.15)")
    g_tune.add_argument("--cl-tol", type=int, default=10,
                        help="Content-length tolerance +/- bytes (default: 10)")
    g_tune.add_argument("--simhash-threshold", type=int, default=10,
                        help="SimHash hamming distance threshold (default: 10)")
    g_tune.add_argument("--min-cluster", type=int, default=5,
                        help="Min cluster size to flag as FP (default: 5)")
    g_tune.add_argument("--reprobe", action="store_true",
                        help="Re-fetch URLs to collect bodies for deep analysis")

    p.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    p.add_argument("--version", action="version", version="api-verifier " + VERSION)
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # FFUF MODE
    if args.ffuf_file:
        if not os.path.isfile(args.ffuf_file):
            parser.error("File not found: " + args.ffuf_file)

        if not args.quiet:
            log(BANNER)

        log("[*] Parsing ffuf output: " + args.ffuf_file)
        entries, meta = parse_ffuf_json(args.ffuf_file)
        log("[*] Loaded %d results from ffuf" % len(entries))
        if meta["commandline"]:
            log("    Command: " + meta["commandline"][:120])

        if not entries:
            log("[!] No results found in ffuf output.")
            sys.exit(0)

        # Optional reprobe for body analysis
        if args.reprobe:
            hdrs = {}
            if args.headers:
                for h in args.headers:
                    if ":" in h:
                        k, v = h.split(":", 1)
                        hdrs[k.strip()] = v.strip()
            http = HTTPEngine(
                threads=args.threads, timeout=args.timeout,
                proxy=args.proxy or "", headers=hdrs,
                cookies=args.cookies or "",
                verify_ssl=not args.no_verify,
            )
            entries = reprobe_entries(entries, http, args.threads, args.rate)

        # Intelligent analysis
        engine = IntelligentFPEngine(
            cl_dominance_pct=args.cl_pct,
            word_dominance_pct=args.wc_pct,
            cl_tolerance=args.cl_tol,
            simhash_threshold=args.simhash_threshold,
            min_cluster_size=args.min_cluster,
        )
        entries = engine.analyze(entries)

        if not args.quiet:
            print_hit_table(entries)

        out_file = args.output or os.path.splitext(args.ffuf_file)[0] + "_clean.json"
        write_results(entries, out_file, include_fp=args.include_fp)

    # LIVE MODE
    elif args.url:
        if not args.wordlist:
            parser.error("Live mode requires -w/--wordlist")
        parsed = urllib.parse.urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            parser.error("URL must include scheme (http:// or https://)")
        scanner = LiveScanner(args)
        scanner.run()

    else:
        parser.error("Specify either -f (ffuf mode) or -u (live mode)")


if __name__ == "__main__":
    main()

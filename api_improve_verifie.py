#!/usr/bin/env python3
"""
API Endpoint False-Positive Verifier v5.0
Two modes: FFUF MODE (-f) and LIVE MODE (-u -w).
v5: Response proof > Path name. Always.
"""
import argparse, collections, hashlib, json, math, os, re, signal, ssl
import statistics, sys, threading, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "5.0.0"
BANNER = "\n   API False-Positive Verifier v5.0.0\n   Response proof > Path name. Always.\n"
RANDOM_SLUGS = [hashlib.md5(os.urandom(8)).hexdigest()[:14] for _ in range(8)]
DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "python-api-verifier/5.0",
]
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.DOTALL)
_CT_STRUCTURED = re.compile(
    r"(application/json|application/xml|text/xml|application/yaml|"
    r"text/yaml|application/x-yaml|application/x-protobuf|"
    r"application/graphql|application/grpc|application/soap\+xml|"
    r"application/vnd\.|application/hal\+json|application/problem\+json|"
    r"text/csv|application/octet-stream)", re.I)
_CT_HTML = re.compile(r"text/html", re.I)

# ===== PATH CLASSIFIER =====
_PATH_PATTERNS = {
    "swagger": re.compile(r"(swagger|swagger-ui|swagger\.json|swagger\.yaml|swagger-resources|swagger-config)", re.I),
    "openapi": re.compile(r"(openapi|openapi\.json|openapi\.yaml|api-docs|api-documentation)", re.I),
    "graphql": re.compile(r"(graphql|graphiql|playground|gql|voyager|altair)", re.I),
    "actuator": re.compile(r"(actuator|actuator/)", re.I),
    "metrics": re.compile(r"(/metrics$|/prometheus|healthz$|readyz$|livez$|health-check|healthcheck|_health$|_status$|_ping$|server-status|server-info|build-info)", re.I),
    "debug": re.compile(r"(debug|phpinfo|info\.php|__debug__|trace\.axd|elmah\.axd|web\.config|WEB-INF|META-INF|jmx-console)", re.I),
    "auth": re.compile(r"(oauth|\.well-known/openid|\.well-known/jwks|connect/token|auth/token|auth/login|saml|oidc|/token$|/authorize$)", re.I),
    "config_leak": re.compile(r"(\.env$|\.git$|\.git/|\.htaccess|\.htpasswd|docker-compose|\.aws/credentials|config\.(json|yaml|yml|xml)$|secrets$|security\.txt|robots\.txt|sitemap\.xml)", re.I),
    "wsdl": re.compile(r"(\?wsdl|\.wsdl|\.xsd|/wsdl$)", re.I),
    "proto": re.compile(r"(\.proto$|grpc|grpc/reflection|twirp)", re.I),
    "redoc": re.compile(r"(redoc|rapidoc|scalar)", re.I),
    "cloud_meta": re.compile(r"(metadata$|computeMetadata|ec2-metadata|kubernetes|k8s/)", re.I),
    "api_json": re.compile(r"\.(json|yaml|yml|xml)$", re.I),
}

_EXPECTED_CT = {
    "swagger": ["json", "yaml", "html"], "openapi": ["json", "yaml"],
    "graphql": ["json", "html"], "redoc": ["html"], "wsdl": ["xml"],
    "proto": ["protobuf", "grpc"], "actuator": ["json"],
    "metrics": ["json", "plain", "openmetrics"], "debug": ["html", "plain"],
    "auth": ["json"], "config_leak": ["plain", "json", "yaml", "xml", "octet"],
    "cloud_meta": ["json", "plain"], "api_json": ["json", "yaml", "xml"],
}

def classify_path(p):
    p = p.lower().rstrip("/")
    for cat, rx in _PATH_PATTERNS.items():
        if rx.search(p):
            return cat
    return "generic"

def ct_matches_category(ct, cat):
    if not ct or cat == "generic":
        return False
    ct = ct.lower()
    return any(e in ct for e in _EXPECTED_CT.get(cat, []))

# ===== BODY ANALYZER =====
class BodyAnalyzer:
    _OA = re.compile(r'"(openapi|swagger|info|paths|components|definitions|basePath|servers)"', re.I)
    _OAY = re.compile(r'^(openapi|swagger|info|paths|components|definitions|basePath):', re.M | re.I)
    _GQL = re.compile(r'"(__schema|__type|data|query|mutation|subscription|types|queryType)"', re.I)
    _GQLS = re.compile(r'(type\s+Query|type\s+Mutation|schema\s*\{|scalar\s+)', re.I)
    _PROM = re.compile(r'^# (HELP|TYPE) \w+', re.M)
    _PROMM = re.compile(r'^\w+(\{[^}]*\})?\s+[\d.e+-]+', re.M)
    _JSON = re.compile(r'^\s*[\{\[]')
    _WSDL = re.compile(r'<(wsdl:definitions|definitions|wsdl:types|xsd:schema)', re.I)
    _ENV = re.compile(r'^[A-Z_][A-Z0-9_]*\s*=\s*.+', re.M)
    _SEC = re.compile(r'(password|secret|api_key|apikey|access_token|private_key|aws_secret|db_password|database_url|jwt_secret)\s*[=:]\s*\S+', re.I)
    _ACT = re.compile(r'"(status|components|details|diskSpace|db|ping|jvm\.memory|system\.cpu|activeProfiles|propertySources|beans|mappings)"', re.I)
    _HTML = re.compile(r'<!DOCTYPE|<html|<head|<body', re.I)

    @classmethod
    def analyze(cls, body, ct="", path=""):
        r = {"type": "unknown", "is_structured": False, "is_api_spec": False,
             "is_config_leak": False, "is_generic_html": False, "score": 0, "tags": [], "detail": ""}
        if not body or len(body.strip()) < 2:
            return r
        bs = body.strip()
        # OpenAPI
        oa = len(cls._OA.findall(body)); oay = len(cls._OAY.findall(body))
        if oa >= 3 or oay >= 3:
            r.update(type="openapi_spec", is_structured=True, is_api_spec=True,
                     score=min(95, 50 + max(oa, oay)*10), detail="OpenAPI spec (%d keys)" % max(oa, oay))
            r["tags"].append("openapi"); return r
        # GraphQL
        gk = len(cls._GQL.findall(body)); gs = len(cls._GQLS.findall(body))
        if gk >= 2 or gs >= 2:
            r.update(type="graphql", is_structured=True, is_api_spec=True,
                     score=min(95, 50+gk*15), detail="GraphQL schema"); r["tags"].append("graphql"); return r
        # WSDL
        if cls._WSDL.search(body):
            r.update(type="wsdl_soap", is_structured=True, is_api_spec=True, score=90, detail="WSDL/SOAP")
            r["tags"].append("wsdl"); return r
        # Prometheus
        ph = len(cls._PROM.findall(body)); pm = len(cls._PROMM.findall(body[:4096]))
        if ph >= 2 or pm >= 5:
            r.update(type="prometheus", is_structured=True, score=min(95, 50+pm*5),
                     detail="Prometheus (%d series)" % pm); r["tags"].append("metrics"); return r
        # Config leak
        ev = len(cls._ENV.findall(body[:2048])); sc = len(cls._SEC.findall(body[:4096]))
        if ev >= 3 or sc >= 1:
            r.update(type="config_leak", is_structured=True, is_config_leak=True,
                     score=min(95, 40+ev*10+sc*20), detail="Config leak (%d vars, %d secrets)" % (ev, sc))
            r["tags"].append("config_leak"); return r
        # Actuator
        am = len(cls._ACT.findall(body))
        if am >= 2:
            r.update(type="actuator", is_structured=True, score=min(90, 50+am*10),
                     detail="Actuator data (%d keys)" % am); r["tags"].append("actuator"); return r
        # JSON
        if cls._JSON.match(bs):
            try:
                parsed = json.loads(bs[:16384])
                r["is_structured"] = True; r["tags"].append("valid_json")
                if isinstance(parsed, dict):
                    keys = {str(k).lower() for k in parsed.keys()}
                    ak = keys & {"data","results","items","records","payload","response","error","errors",
                                 "message","code","status","count","total","page","meta","version","id"}
                    if ak:
                        r.update(type="api_response", score=min(85, 30+len(ak)*12),
                                 detail="JSON API (%s)" % ",".join(sorted(ak)[:4]))
                        r["tags"].append("api_response"); return r
                    r.update(type="json_data", score=50+min(30, len(keys)*3),
                             detail="JSON (%d keys)" % len(keys)); return r
                elif isinstance(parsed, list):
                    r.update(type="json_array", score=50+min(30, len(parsed)*2),
                             detail="JSON array (%d)" % len(parsed)); return r
            except (json.JSONDecodeError, ValueError):
                pass
        # HTML
        if cls._HTML.search(body[:1024]):
            r.update(type="html_page", is_generic_html=True, score=5, detail="Generic HTML page"); return r
        r.update(type="plain_text", score=15, detail="Plain text (%d bytes)" % len(body)); return r

# ===== SIMHASH =====
class SimHash:
    __slots__ = ("value",)
    def __init__(self, data, bits=64):
        v = [0]*bits
        for t in self._shingle(data):
            h = int(hashlib.md5(t.encode("utf-8","replace")).hexdigest(), 16)
            for i in range(bits):
                v[i] += 1 if h & (1 << i) else -1
        self.value = sum(1 << i for i in range(bits) if v[i] > 0)
    @staticmethod
    def _shingle(text):
        text = re.sub(r"\s+", " ", text.lower().strip())
        return [text[i:i+4] for i in range(max(0, len(text)-3))] if len(text) >= 4 else ([text] if text else [])
    @staticmethod
    def hamming(a, b):
        x = a ^ b; c = 0
        while x: c += 1; x &= x - 1
        return c

# ===== DATA =====
@dataclass
class FfufEntry:
    url: str; fuzz_word: str; input_map: Dict[str, str]
    status: int; length: int; words: int; lines: int
    content_type: str; redirect_location: str; duration_ns: int
    host: str; position: int
    body: str = ""; simhash: int = 0; title: str = ""
    is_fp: bool = False; fp_reason: str = ""; confidence: str = ""
    body_hash: str = ""; path_category: str = ""
    content_analysis: str = ""; content_score: int = 0; content_tags: str = ""
    @property
    def duration_ms(self): return self.duration_ns / 1_000_000
    @property
    def path(self): return urllib.parse.urlparse(self.url).path or "/"
    @property
    def fingerprint(self): return (self.length, self.words, self.lines)

# ===== FFUF PARSER =====
def parse_ffuf_json(filepath):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        raw = json.load(f)
    meta = {"commandline": raw.get("commandline", ""), "time": raw.get("time", ""),
            "total_results": len(raw.get("results", []))}
    entries = []
    for r in raw.get("results", []):
        inp = r.get("input", {})
        im = {k: str(v) for k, v in inp.items()} if isinstance(inp, dict) else {"FUZZ": str(inp)}
        fw = im.get("FUZZ", next(iter(im.values()), ""))
        entries.append(FfufEntry(
            url=r.get("url",""), fuzz_word=fw, input_map=im,
            status=int(r.get("status",0)), length=int(r.get("length",0)),
            words=int(r.get("words",0)), lines=int(r.get("lines",0)),
            content_type=r.get("content-type", r.get("content_type","")),
            redirect_location=r.get("redirectlocation",""),
            duration_ns=int(r.get("duration",0)), host=r.get("host",""),
            position=int(r.get("position",0))))
    return entries, meta

# ===== v5 FP ENGINE =====
class FPEngine:
    """Response proof > Path name. Always."""
    def __init__(self, cl_tol=10, sh_thr=10):
        self.cl_tol = cl_tol; self.sh_thr = sh_thr

    def analyze(self, entries):
        if not entries: return entries
        total = len(entries)
        log("[*] v5 FP Engine: %d results" % total)

        # Phase 1: dominant fingerprints
        fpc = collections.Counter(e.fingerprint for e in entries)
        dominant = []
        log("  [Phase 1] Response fingerprints:")
        for fp, cnt in fpc.most_common(5):
            pct = cnt/total*100
            log("    CL=%-6d W=%-5d L=%-5d -> %dx (%.1f%%)" % (fp[0],fp[1],fp[2],cnt,pct))
            if pct >= 10.0 or cnt >= 10:
                dominant.append(fp)

        if not dominant:
            log("    No dominant fingerprint -- all unique")
            for e in entries:
                e.path_category = classify_path(e.fuzz_word or e.path)
                e.confidence = "HIGH"; e.fp_reason = "unique_fingerprint"
            return entries

        ca_pct = sum(fpc[fp] for fp in dominant)/total*100
        log("    Catch-all coverage: %.1f%%" % ca_pct)
        if ca_pct >= 60:
            log("    ** FULL CATCH-ALL ** Path names meaningless without proof")

        clc = collections.Counter(e.length for e in entries)
        fp_count = ver_count = 0

        # Phase 2: classify each
        log("  [Phase 2] Classifying (response proof > path name)...")
        for e in entries:
            e.path_category = classify_path(e.fuzz_word or e.path)
            ct = (e.content_type or "").lower()
            is_sct = bool(_CT_STRUCTURED.search(ct))
            is_hct = bool(_CT_HTML.search(ct))
            matches_ca = any(abs(e.length-d[0]) <= self.cl_tol and e.words==d[1] and e.lines==d[2] for d in dominant)
            reasons = []; is_fp = False

            if matches_ca:
                reasons.append("matches_catchall(CL=%d,W=%d,L=%d)" % e.fingerprint)
                if is_sct and ct_matches_category(ct, e.path_category):
                    reasons.append("RESCUED:ct_matches_path(%s+%s)" % (e.path_category, ct.split(";")[0].strip()))
                elif e.content_score >= 50:
                    reasons.append("RESCUED:body_verified(score=%d)" % e.content_score)
                elif is_sct and not is_hct and e.content_score >= 30:
                    reasons.append("RESCUED:structured_ct+body(score=%d)" % e.content_score)
                else:
                    is_fp = True
                    if e.path_category != "generic":
                        reasons.append("FP:path_%s_but_html_catchall" % e.path_category)
                    else:
                        reasons.append("FP:generic_catchall")
            else:
                reasons.append("unique_response(CL=%d,W=%d,L=%d)" % e.fingerprint)
                cl_pct = clc.get(e.length,0)/total*100
                if cl_pct >= 15 and is_hct and e.content_score < 30:
                    is_fp = True; reasons.append("FP:common_cl(%.1f%%)+html" % cl_pct)
                elif cl_pct >= 30 and e.content_score < 30:
                    is_fp = True; reasons.append("FP:very_common_cl(%.1f%%)" % cl_pct)

            # Auth status rescue
            if is_fp and e.status in (401, 403, 405):
                ss = sum(1 for x in entries if x.status == e.status)
                if ss/total < 0.2:
                    is_fp = False; reasons.append("RESCUED:auth_status_%d" % e.status)

            # Time outlier rescue
            if is_fp and total > 10:
                times = [x.duration_ms for x in entries if x.duration_ms > 0]
                if len(times) > 2:
                    tm = statistics.mean(times); ts = statistics.stdev(times)
                    if ts > 0 and e.duration_ms > 0:
                        z = (e.duration_ms - tm) / ts
                        if z > 3.0:
                            is_fp = False; reasons.append("RESCUED:time_outlier(z=%.1f)" % z)

            e.is_fp = is_fp; e.fp_reason = "; ".join(reasons)
            if is_fp: fp_count += 1
            else: ver_count += 1

        # Confidence
        for e in entries:
            if e.is_fp: e.confidence = "FP"; continue
            s = 0; ct = (e.content_type or "").lower()
            if not any(abs(e.length-d[0])<=self.cl_tol and e.words==d[1] and e.lines==d[2] for d in dominant): s += 25
            if _CT_STRUCTURED.search(ct): s += 25
            if e.content_score >= 50: s += 25
            if e.status in (401,403,405): s += 20
            if clc.get(e.length,0) <= 2: s += 15
            if e.path_category != "generic" and ct_matches_category(ct, e.path_category): s += 15
            e.confidence = "HIGH" if s >= 50 else ("MEDIUM" if s >= 25 else "LOW")

        log("  [Result] FPs: %d (%.1f%%), Verified: %d" % (fp_count, fp_count/total*100, ver_count))
        return entries

# ===== HTTP ENGINE =====
class HTTPEngine:
    def __init__(self, threads, timeout, proxy, headers, cookies, verify_ssl):
        self.timeout = timeout; self.headers = headers; self._ua_idx = 0; self._lock = threading.Lock()
        if HAS_REQUESTS:
            self.session = requests.Session()
            retry = Retry(total=2, backoff_factor=0.2, status_forcelist=[502,503,504])
            adapter = HTTPAdapter(max_retries=retry, pool_connections=min(threads,100), pool_maxsize=threads)
            self.session.mount("https://", adapter); self.session.mount("http://", adapter)
            self.session.verify = verify_ssl
            if proxy: self.session.proxies = {"http": proxy, "https": proxy}
            if cookies:
                for p in cookies.split(";"):
                    p = p.strip()
                    if "=" in p:
                        k, v = p.split("=", 1)
                        self.session.cookies.set(k.strip(), v.strip())
        else:
            self.session = None
            if not verify_ssl: ssl._create_default_https_context = ssl._create_unverified_context

    def _ua(self):
        with self._lock:
            ua = DEFAULT_UAS[self._ua_idx % len(DEFAULT_UAS)]; self._ua_idx += 1; return ua

    def get(self, url):
        h = dict(self.headers); h["User-Agent"] = self._ua(); t0 = time.perf_counter()
        try:
            if HAS_REQUESTS and self.session:
                r = self.session.get(url, headers=h, timeout=self.timeout, allow_redirects=False, stream=False)
                el = (time.perf_counter()-t0)*1000
                return {"status": r.status_code, "length": len(r.content), "body": r.text[:16384],
                        "time_ms": round(el,1), "headers": dict(r.headers),
                        "redirect": r.headers.get("Location",""), "error": None}
            else:
                import urllib.request
                req = urllib.request.Request(url, headers=h)
                resp = urllib.request.urlopen(req, timeout=self.timeout)
                body = resp.read(16384).decode("utf-8","replace")
                el = (time.perf_counter()-t0)*1000
                return {"status": resp.status, "length": len(body), "body": body,
                        "time_ms": round(el,1), "headers": dict(resp.headers), "redirect": "", "error": None}
        except Exception as ex:
            return {"status": 0, "length": 0, "body": "", "headers": {},
                    "time_ms": round((time.perf_counter()-t0)*1000,1), "redirect": "", "error": str(ex)[:120]}

# ===== REPROBE =====
def reprobe_entries(entries, http, threads, rate=0):
    log("[*] Re-probing %d URLs..." % len(entries))
    delay = 1.0/rate if rate > 0 else 0
    lock = threading.Lock(); done = [0]; total = len(entries)
    def probe(e):
        if delay: time.sleep(delay)
        r = http.get(e.url)
        if r["error"]: return
        body = r["body"]; e.body = body
        if body:
            e.simhash = SimHash(body).value
            e.body_hash = hashlib.md5(body.encode("utf-8","replace")).hexdigest()[:16]
            m = _TITLE_RE.search(body)
            if m: e.title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            ct = r["headers"].get("Content-Type", r["headers"].get("content-type", ""))
            if ct and not e.content_type: e.content_type = ct
            a = BodyAnalyzer.analyze(body, e.content_type, e.fuzz_word)
            e.content_analysis = a["detail"]; e.content_score = a["score"]
            e.content_tags = "; ".join(a["tags"]) if a["tags"] else ""
        with lock:
            done[0] += 1
            if done[0] % 200 == 0: log("  [reprobe] %d/%d" % (done[0], total))
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = [pool.submit(probe, e) for e in entries]
        for f in as_completed(futs):
            try: f.result()
            except: pass
    log("  [reprobe] Done. Bodies: %d/%d" % (sum(1 for e in entries if e.body), total))
    return entries

# ===== BASELINE =====
def learn_baseline(base_url, http):
    log("[*] Learning baseline...")
    sts = set(); cls = set(); shs = []
    for slug in RANDOM_SLUGS:
        r = http.get(base_url + "/" + slug)
        if r["error"]: continue
        sts.add(r["status"]); cls.add(r["length"])
        if r["body"]: shs.append(SimHash(r["body"]).value)
    log("    Baseline: statuses=%s, CLs=%s" % (sts, cls))
    return sts, cls, shs

# ===== OUTPUT =====
def write_results(entries, fp, include_fp=False):
    out = entries if include_fp else [e for e in entries if not e.is_fp]
    ext = os.path.splitext(fp)[1].lower()
    if ext == ".json":
        data = []
        for e in out:
            row = {"url": e.url, "path": e.path, "fuzz": e.fuzz_word,
                   "status": e.status, "length": e.length, "words": e.words, "lines": e.lines,
                   "content_type": e.content_type, "redirect": e.redirect_location,
                   "duration_ms": round(e.duration_ms,1), "host": e.host,
                   "confidence": e.confidence, "path_category": e.path_category, "fp_reason": e.fp_reason}
            if include_fp: row["is_false_positive"] = e.is_fp
            if e.title: row["title"] = e.title
            if e.body_hash: row["body_hash"] = e.body_hash
            if e.content_analysis: row["content_analysis"] = e.content_analysis
            if e.content_score: row["content_score"] = e.content_score
            if e.content_tags: row["content_tags"] = e.content_tags
            if len(e.input_map) > 1: row["inputs"] = e.input_map
            data.append(row)
        with open(fp, "w") as f: json.dump(data, f, indent=2)
    elif ext == ".csv":
        with open(fp, "w") as f:
            f.write("url,path,fuzz,status,length,words,lines,content_type,confidence,path_category,content_score,content_analysis,duration_ms,is_fp,fp_reason\n")
            for e in out:
                f.write('"%s","%s","%s",%d,%d,%d,%d,"%s",%s,"%s",%d,"%s",%.1f,%s,"%s"\n' % (
                    e.url, e.path, e.fuzz_word, e.status, e.length, e.words, e.lines,
                    e.content_type, e.confidence, e.path_category, e.content_score,
                    (e.content_analysis or "").replace('"','""'), e.duration_ms, e.is_fp,
                    (e.fp_reason or "").replace('"','""')))
    else:
        with open(fp, "w") as f:
            for e in out: f.write(e.url + "\n")
    log("[+] Saved %d hits to %s" % (sum(1 for e in out if not e.is_fp), fp))

def _sc(code):
    if 200 <= code < 300: return "\033[92m"
    if 300 <= code < 400: return "\033[93m"
    if code in (401,403): return "\033[91m"
    if code == 405: return "\033[95m"
    return "\033[96m"

def print_hit_table(entries):
    ver = [e for e in entries if not e.is_fp]
    if not ver: log("[*] No verified endpoints."); return
    rst = "\033[0m"
    log("\n" + "="*110 + "\n VERIFIED ENDPOINTS (%d)\n" % len(ver) + "="*110)
    log("%-8s %-10s %-8s %-8s %-6s %-14s %s" % ("Status","Length","Words","Lines","Conf","Category","URL + Evidence"))
    log("-"*110)
    for e in sorted(ver, key=lambda x: (x.confidence!="HIGH", -x.content_score, x.path)):
        ev = "  [%s]" % e.content_analysis if e.content_analysis else ""
        ct = (e.content_type or "").split(";")[0].strip()
        if ct: ev += "  (%s)" % ct
        print("%s%-8d%s %-10d %-8d %-8d %-6s %-14s %s%s" % (
            _sc(e.status), e.status, rst, e.length, e.words, e.lines,
            e.confidence, e.path_category[:13], e.url, ev), flush=True)

# ===== LIVE SCANNER =====
class LiveScanner:
    def __init__(self, args):
        self.base = args.url.rstrip("/"); self.wl = args.wordlist
        self.threads = args.threads; self.output = args.output; self.quiet = args.quiet
        hdrs = {}
        if args.headers:
            for h in args.headers:
                if ":" in h: k,v=h.split(":",1); hdrs[k.strip()]=v.strip()
        self.http = HTTPEngine(self.threads, args.timeout, args.proxy or "", hdrs,
                               args.cookies or "", not args.no_verify)
        self.mc = set(int(c) for c in args.mc.split(",")) if args.mc else None
        self.fc = set(int(c) for c in args.fc.split(",")) if args.fc else None
        self.hits=[]; self._lock=threading.Lock(); self._stop=threading.Event()
        self._done=0; self._errs=0; self._fps=0

    def run(self):
        if not self.quiet: log(BANNER)
        total = sum(1 for _ in open(self.wl))
        log("[*] %d paths | %d threads | %s" % (total, self.threads, self.base))
        bl_s, bl_c, bl_sh = learn_baseline(self.base, self.http)
        signal.signal(signal.SIGINT, lambda s,f: self._stop.set())
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futs = {}; fin = False
            gen = (l.strip() for l in open(self.wl) if l.strip())
            gen = (p if p.startswith("/") else "/"+p for p in gen)
            while not self._stop.is_set():
                while len(futs) < self.threads*4 and not fin:
                    try: p = next(gen); futs[pool.submit(self._probe, p, bl_s, bl_c, bl_sh)] = p
                    except StopIteration: fin = True; break
                if not futs: break
                dl = [f for f in futs if f.done()]
                if not dl: time.sleep(0.01); continue
                for f in dl:
                    futs.pop(f); self._done += 1
                    try:
                        h = f.result()
                        if h:
                            with self._lock: self.hits.append(h)
                    except: pass
        el = time.perf_counter()-t0
        log("[+] %.1fs | %d req | %d hits | %d FPs" % (el, self._done, len(self.hits), self._fps))
        if self.output and self.hits: write_results(self.hits, self.output)

    def _probe(self, path, bl_s, bl_c, bl_sh):
        if self._stop.is_set(): return None
        url = self.base + path; r = self.http.get(url)
        if r["error"]: self._errs += 1; return None
        st = r["status"]
        if self.mc and st not in self.mc: return None
        if self.fc and st in self.fc: return None
        if st in (404,410,501): return None
        body = r["body"]; length = r["length"]; ct = r["headers"].get("Content-Type","")
        is_sct = bool(_CT_STRUCTURED.search(ct))
        a = BodyAnalyzer.analyze(body, ct, path) if body else {"score":0,"tags":[],"detail":""}
        cl_match = any(abs(length-b)<=15 for b in bl_c)
        sh_match = False
        if body and bl_sh:
            sh = SimHash(body); sh_match = any(SimHash.hamming(sh.value,b)<=10 for b in bl_sh)
        if cl_match or sh_match:
            if not (is_sct and a["score"]>=40) and not (a["score"]>=60) and st not in (401,403,405):
                self._fps += 1; return None
        cat = classify_path(path)
        s = 0
        if not cl_match and not sh_match: s += 25
        if is_sct: s += 25
        if a["score"] >= 50: s += 25
        if st in (401,403,405): s += 20
        conf = "HIGH" if s>=50 else ("MEDIUM" if s>=25 else "LOW")
        bh = hashlib.md5(body.encode("utf-8","replace")).hexdigest()[:16] if body else ""
        return FfufEntry(url=url, fuzz_word=path, input_map={"FUZZ":path},
            status=st, length=length, words=0, lines=0, content_type=ct,
            redirect_location=r["redirect"], duration_ns=int(r["time_ms"]*1e6),
            host="", position=0, body=body[:1024], simhash=SimHash(body).value if body else 0,
            confidence=conf, body_hash=bh, path_category=cat,
            content_analysis=a["detail"], content_score=a["score"],
            content_tags="; ".join(a["tags"]))

# ===== LOGGING =====
def log(msg): sys.stderr.write(msg + "\n"); sys.stderr.flush()

# ===== CLI =====
def build_parser():
    p = argparse.ArgumentParser(description="API FP Verifier v5 -- response proof > path name",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-f", "--ffuf-file", help="ffuf JSON output")
    p.add_argument("-u", "--url", help="Target URL (live mode)")
    p.add_argument("-w", "--wordlist", help="Wordlist (live mode)")
    p.add_argument("-o", "--output", help="Output file (.json/.csv/.txt)")
    p.add_argument("--include-fp", action="store_true", help="Include FPs in output")
    p.add_argument("-t", "--threads", type=int, default=50)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("-H", "--headers", action="append")
    p.add_argument("--cookies", help="Cookies string")
    p.add_argument("--proxy", help="HTTP proxy")
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--rate", type=float, default=0)
    p.add_argument("--mc", help="Match status codes")
    p.add_argument("--fc", help="Filter status codes")
    p.add_argument("--follow-redirects", action="store_true")
    p.add_argument("--deep", action="store_true")
    p.add_argument("--cl-tol", type=int, default=10, help="CL tolerance (default: 10)")
    p.add_argument("--simhash-threshold", type=int, default=10)
    p.add_argument("--reprobe", action="store_true", help="Re-fetch to verify body")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--version", action="version", version="api-verifier " + VERSION)
    return p

def main():
    parser = build_parser(); args = parser.parse_args()
    if args.ffuf_file:
        if not os.path.isfile(args.ffuf_file): parser.error("Not found: " + args.ffuf_file)
        if not args.quiet: log(BANNER)
        log("[*] Parsing: " + args.ffuf_file)
        entries, meta = parse_ffuf_json(args.ffuf_file)
        log("[*] Loaded %d results" % len(entries))
        if meta["commandline"]: log("    Cmd: " + meta["commandline"][:120])
        if not entries: log("[!] No results."); sys.exit(0)
        if args.reprobe:
            hdrs = {}
            if args.headers:
                for h in args.headers:
                    if ":" in h: k,v=h.split(":",1); hdrs[k.strip()]=v.strip()
            http = HTTPEngine(args.threads, args.timeout, args.proxy or "", hdrs,
                              args.cookies or "", not args.no_verify)
            entries = reprobe_entries(entries, http, args.threads, args.rate)
        engine = FPEngine(cl_tol=args.cl_tol, sh_thr=args.simhash_threshold)
        entries = engine.analyze(entries)
        if not args.quiet: print_hit_table(entries)
        of = args.output or os.path.splitext(args.ffuf_file)[0] + "_clean.json"
        write_results(entries, of, include_fp=args.include_fp)
    elif args.url:
        if not args.wordlist: parser.error("Need -w")
        p = urllib.parse.urlparse(args.url)
        if not p.scheme or not p.netloc: parser.error("URL needs scheme")
        LiveScanner(args).run()
    else:
        parser.error("Need -f or -u")

if __name__ == "__main__":
    main()

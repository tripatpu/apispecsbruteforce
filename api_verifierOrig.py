#!/usr/bin/env python3
"""
API Endpoint False-Positive Verifier v3.0
==========================================
Two modes:
  1. FFUF MODE (-f):  Parse ffuf JSON output, remove false positives offline
                      using statistical clustering + optional live re-probe.
  2. LIVE MODE (-u -w): Fuzz a target directly with threaded scanning.

False-positive detection layers:
  L1  Content-length frequency clustering (dominant CL = generic page)
  L2  Word-count / line-count clustering
  L3  SimHash body similarity (re-probe or cached bodies)
  L4  Response-time outlier analysis
  L5  Title / body keyword soft-404 detection
  L6  Adaptive frequency spike detection (live mode)
  L7  Content-type consistency checks
  L8  Redirect-chain deduplication

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

VERSION = "3.0.0"
BANNER = r"""
   ___    ____  ____   _    __          _ ____
  / _ |  / __ \/  _/  | |  / /__  ____(_) __/_  __
 / __ | / /_/ // /    | | / / _ \/ __/ / /_/ / / /
/_/ |_|/ .___/___/    | |/ /  __/ /  / / __/ /_/ /
      /_/             |___/\___/_/  /_/_/  \__, /
   False-Positive Verifier  v3.0.0        /____/
"""

RANDOM_SLUGS = [hashlib.md5(os.urandom(8)).hexdigest()[:14] for _ in range(8)]

DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/17.5",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "python-api-verifier/3.0",
]

SOFT_404_KEYWORDS = frozenset({
    "page not found", "not found", "404", "does not exist",
    "cannot be found", "no route", "invalid endpoint", "resource not found",
    "nothing here", "the page you requested", "unavailable",
    "doesn't exist", "could not find", "no such", "error 404",
    "this page doesn't", "oops", "we couldn't find",
})

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.DOTALL)


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


# ========================= CLUSTER FP ENGINE ================================
class ClusterFPEngine:
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
        log("[*] Analyzing %d ffuf results for false positives...\n" % total)

        # L1: Content-Length clustering
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
            log("  [L1] Dominant content-lengths (>=%d%% of results):" % int(self.cl_dominance_pct * 100))
            for cl in sorted(dominant_cls):
                cnt = cl_counter[cl]
                log("       CL=%d appears %dx (%.1f%%)" % (cl, cnt, cnt / total * 100))

        # L2: Word-count clustering
        wc_counter = collections.Counter(e.words for e in entries)
        dominant_wcs = set()
        for wc, count in wc_counter.most_common():
            if count / total >= self.word_dominance_pct:
                dominant_wcs.add(wc)

        if dominant_wcs:
            log("  [L2] Dominant word-counts:")
            for wc in sorted(dominant_wcs):
                cnt = wc_counter[wc]
                log("       Words=%d appears %dx (%.1f%%)" % (wc, cnt, cnt / total * 100))

        # L3: Line-count clustering
        lc_counter = collections.Counter(e.lines for e in entries)
        dominant_lcs = set()
        for lc, count in lc_counter.most_common():
            if count / total >= self.word_dominance_pct:
                dominant_lcs.add(lc)

        if dominant_lcs:
            log("  [L3] Dominant line-counts:")
            for lc in sorted(dominant_lcs):
                cnt = lc_counter[lc]
                log("       Lines=%d appears %dx (%.1f%%)" % (lc, cnt, cnt / total * 100))

        # L4: Content-Type clustering
        ct_counter = collections.Counter(
            (e.content_type.split(";")[0].strip().lower() if e.content_type else "")
            for e in entries
        )
        dominant_ct = ""
        if ct_counter:
            dominant_ct, ct_count = ct_counter.most_common(1)[0]
            if ct_count / total >= 0.5:
                log("  [L4] Dominant content-type: '%s' (%dx, %.1f%%)" % (dominant_ct, ct_count, ct_count / total * 100))

        # L5: Response time stats
        times = [e.duration_ms for e in entries if e.duration_ms > 0]
        time_mean = statistics.mean(times) if times else 0
        time_stdev = statistics.stdev(times) if len(times) > 2 else 0
        if time_mean:
            log("  [L5] Response times: mean=%.0fms, stdev=%.0fms" % (time_mean, time_stdev))

        # L6: Redirect clustering
        redir_counter = collections.Counter(
            e.redirect_location for e in entries if e.redirect_location
        )
        dominant_redirs = set()
        for loc, count in redir_counter.most_common():
            if count >= self.min_cluster_size:
                dominant_redirs.add(loc)

        if dominant_redirs:
            log("  [L6] Dominant redirect targets (%d unique):" % len(dominant_redirs))
            for loc in list(dominant_redirs)[:5]:
                log("       -> %s (%dx)" % (loc, redir_counter[loc]))

        # L7: SimHash clustering (if bodies populated via reprobe)
        body_simhashes = [(i, e.simhash) for i, e in enumerate(entries) if e.simhash]
        simhash_fp_indices = set()
        if body_simhashes:
            sh_counter = collections.Counter(sh for _, sh in body_simhashes)
            dominant_sh_val, dominant_sh_count = sh_counter.most_common(1)[0]
            if dominant_sh_count / total >= 0.1:
                log("  [L7] Dominant SimHash cluster: %d entries" % dominant_sh_count)
                for idx, sh in body_simhashes:
                    if SimHash.hamming(sh, dominant_sh_val) <= self.simhash_threshold:
                        simhash_fp_indices.add(idx)

        # L8: Body-hash exact-duplicate clustering
        bh_counter = collections.Counter(e.body_hash for e in entries if e.body_hash)
        dominant_body_hashes = set()
        for bh, count in bh_counter.most_common():
            if count / total >= self.cl_dominance_pct and count >= self.min_cluster_size:
                dominant_body_hashes.add(bh)

        if dominant_body_hashes:
            log("  [L8] Dominant body hashes: %d cluster(s)" % len(dominant_body_hashes))

        # =============== CLASSIFY ===============
        log("\n[*] Classifying entries...")
        fp_count = 0
        reasons_counter = collections.Counter()

        for i, e in enumerate(entries):
            reasons = []

            # CL match
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

            if e.title:
                title_lower = e.title.lower()
                for kw in SOFT_404_KEYWORDS:
                    if kw in title_lower:
                        reasons.append("soft404_title")
                        break

            if e.body:
                body_lower = e.body.lower()
                for kw in SOFT_404_KEYWORDS:
                    if kw in body_lower:
                        reasons.append("soft404_body")
                        break

            # DECISION: FP if 2+ independent signals, or CL+WC combo
            is_fp = False
            if len(reasons) >= 2:
                is_fp = True
            elif cl_match and e.words in dominant_wcs and e.lines in dominant_lcs:
                is_fp = True
            elif len(reasons) == 1:
                r = reasons[0]
                if r == "cl_cluster":
                    for dcl in dominant_cls:
                        if abs(e.length - dcl) <= self.cl_tolerance:
                            if cl_counter.get(dcl, 0) / total >= 0.50:
                                is_fp = True
                            break
                elif r in ("body_hash_cluster", "simhash_cluster"):
                    is_fp = True

            # Override: protect high-value status codes
            if is_fp and e.status in (401, 403, 405):
                status_count = sum(1 for x in entries if x.status == e.status)
                if status_count / total < 0.3:
                    is_fp = False
                    reasons.append("protected_by_status")

            # Override: response time outlier
            if is_fp and time_stdev > 0 and e.duration_ms > 0:
                zscore = (e.duration_ms - time_mean) / time_stdev
                if zscore > self.time_zscore:
                    is_fp = False
                    reasons.append("time_outlier_z=%.1f" % zscore)

            e.is_fp = is_fp
            e.fp_reason = "; ".join(reasons) if reasons else "unique"
            e.confidence = self._rate_confidence(e, dominant_cls, dominant_wcs, total, cl_counter)

            if is_fp:
                fp_count += 1
                for r in reasons:
                    reasons_counter[r] += 1

        log("\n[*] Classification complete:")
        log("    Total:           %d" % total)
        log("    False positives: %d" % fp_count)
        log("    Verified hits:   %d" % (total - fp_count))
        if reasons_counter:
            log("    FP breakdown:")
            for reason, cnt in reasons_counter.most_common():
                log("      %s: %d" % (reason, cnt))

        return entries

    def _rate_confidence(self, e, dominant_cls, dominant_wcs, total, cl_counter):
        if e.is_fp:
            return "FP"
        if e.status in (401, 403, 405):
            return "HIGH"
        if e.status in (200, 201) and e.length > 100:
            ct = (e.content_type or "").lower()
            if any(x in ct for x in ["json", "xml", "yaml", "protobuf"]):
                return "HIGH"
            cl_freq = cl_counter.get(e.length, 0)
            if cl_freq <= 3:
                return "HIGH"
            elif cl_freq / total < 0.05:
                return "MEDIUM"
            return "MEDIUM"
        if e.status in (301, 302, 307, 308):
            return "MEDIUM"
        if e.status == 204:
            return "MEDIUM"
        if e.status >= 500:
            return "LOW"
        return "MEDIUM"


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
                    "body": r.text[:8192], "time_ms": round(elapsed, 1),
                    "headers": dict(r.headers),
                    "redirect": r.headers.get("Location", ""),
                    "error": None,
                }
            else:
                import urllib.request
                req = urllib.request.Request(url, headers=merged)
                resp = urllib.request.urlopen(req, timeout=self.timeout)
                body = resp.read(8192).decode("utf-8", "replace")
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
                "fp_reason": e.fp_reason,
            }
            if include_fp:
                row["is_false_positive"] = e.is_fp
            if e.title:
                row["title"] = e.title
            if e.body_hash:
                row["body_hash"] = e.body_hash
            if len(e.input_map) > 1:
                row["inputs"] = e.input_map
            data.append(row)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    elif ext == ".csv":
        with open(filepath, "w") as f:
            f.write("url,path,fuzz,status,length,words,lines,content_type,confidence,duration_ms,redirect,title,body_hash,is_fp,fp_reason\n")
            for e in out:
                title_esc = e.title.replace('"', '""')
                reason_esc = e.fp_reason.replace('"', '""')
                f.write('"%s","%s","%s",%d,%d,%d,%d,"%s",%s,%.1f,"%s","%s",%s,%s,"%s"\n' % (
                    e.url, e.path, e.fuzz_word, e.status, e.length,
                    e.words, e.lines, e.content_type, e.confidence,
                    e.duration_ms, e.redirect_location, title_esc,
                    e.body_hash, e.is_fp, reason_esc))

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


def print_hit_table(entries):
    verified = [e for e in entries if not e.is_fp]
    if not verified:
        log("[*] No verified endpoints found after filtering.")
        return

    log("\n" + "=" * 100)
    log(" VERIFIED ENDPOINTS (%d hits)" % len(verified))
    log("=" * 100)
    log("%-8s %-10s %-8s %-8s %-10s %-6s %s" % ("Status", "Length", "Words", "Lines", "Time(ms)", "Conf", "URL"))
    log("%-8s %-10s %-8s %-8s %-10s %-6s %s" % ("-" * 6, "-" * 8, "-" * 6, "-" * 6, "-" * 8, "-" * 5, "-" * 40))

    for e in sorted(verified, key=lambda x: (x.confidence != "HIGH", x.status, x.path)):
        sc = _status_color(e.status)
        rst = "\033[0m"
        redir = " -> " + e.redirect_location if e.redirect_location else ""
        title = '  "%s"' % e.title if e.title else ""
        print("%s%-8d%s %-10d %-8d %-8d %-10.0f %-6s %s%s%s" % (
            sc, e.status, rst, e.length, e.words, e.lines,
            e.duration_ms, e.confidence, e.url, redir, title), flush=True)


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
        if st in bl_statuses and st not in (200, 201, 301, 302, 307, 308, 401, 403, 405):
            self._fps += 1
            return None

        body = resp["body"]
        length = resp["length"]

        for bcl in bl_cls:
            if abs(length - bcl) <= 15:
                if body and bl_shs:
                    sh = SimHash(body)
                    for bsh in bl_shs:
                        if SimHash.hamming(sh.value, bsh) <= 10:
                            self._fps += 1
                            return None
                elif not body:
                    self._fps += 1
                    return None
                break

        if body and bl_shs:
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

        if st in (401, 403, 405):
            conf = "HIGH"
        elif st in (200, 201) and length > 100:
            conf = "HIGH"
        else:
            conf = "MEDIUM"

        bh = hashlib.md5(body.encode("utf-8", "replace")).hexdigest()[:16] if body else ""
        sh_val = SimHash(body).value if body else 0

        return FfufEntry(
            url=url, fuzz_word=path, input_map={"FUZZ": path},
            status=st, length=length, words=0, lines=0,
            content_type=resp["headers"].get("Content-Type", ""),
            redirect_location=resp["redirect"],
            duration_ns=int(resp["time_ms"] * 1_000_000),
            host="", position=0, body=body[:512], simhash=sh_val,
            title=title, confidence=conf, body_hash=bh,
        )

    def _print_live_hit(self, e):
        sc = _status_color(e.status)
        rst = "\033[0m"
        redir = " -> " + e.redirect_location if e.redirect_location else ""
        title = ' "%s"' % e.title if e.title else ""
        print("%s[%d]%s  CL:%-8d %7.0fms  [%s]  %s%s%s" % (
            sc, e.status, rst, e.length, e.duration_ms,
            e.confidence, e.fuzz_word, redir, title), flush=True)


# ========================= LOGGING ==========================================
def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


# ========================= CLI ==============================================
def build_parser():
    p = argparse.ArgumentParser(
        description="API False-Positive Verifier v3 -- ffuf output parser + live scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
FFUF MODE (parse existing results, remove false positives):
  %(prog)s -f ffuf_output.json -o clean.json
  %(prog)s -f ffuf_output.json -o clean.csv --include-fp
  %(prog)s -f ffuf_output.json --reprobe -t 50 -o clean.json
  %(prog)s -f ffuf_output.json --reprobe --proxy http://127.0.0.1:8080 -o clean.json
  %(prog)s -f ffuf_output.json --cl-pct 0.10 --simhash-threshold 8

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
    g_mode.add_argument("-f", "--ffuf-file", help="Path to ffuf JSON output file (ffuf mode)")
    g_mode.add_argument("-u", "--url", help="Target base URL (live mode)")
    g_mode.add_argument("-w", "--wordlist", help="Wordlist file (live mode)")

    g_out = p.add_argument_group("Output")
    g_out.add_argument("-o", "--output", help="Output file (.json, .csv, .txt)")
    g_out.add_argument("--include-fp", action="store_true",
                       help="Include false positives in output (tagged, not removed)")

    g_net = p.add_argument_group("Network")
    g_net.add_argument("-t", "--threads", type=int, default=50, help="Threads (default: 50)")
    g_net.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout (default: 10s)")
    g_net.add_argument("-H", "--headers", action="append", help="Custom header: -H 'Key: Value'")
    g_net.add_argument("--cookies", help="Cookies: 'k1=v1; k2=v2'")
    g_net.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    g_net.add_argument("--no-verify", action="store_true", help="Skip SSL verification")
    g_net.add_argument("--rate", type=float, default=0, help="Max requests/sec for reprobe (0=unlimited)")

    g_filter = p.add_argument_group("Filtering (live mode)")
    g_filter.add_argument("--mc", help="Match status codes (e.g. 200,301,401)")
    g_filter.add_argument("--fc", help="Filter status codes (e.g. 404,500)")
    g_filter.add_argument("--follow-redirects", action="store_true")
    g_filter.add_argument("--deep", action="store_true", help="Double-probe to confirm hits")

    g_tune = p.add_argument_group("FP tuning")
    g_tune.add_argument("--cl-pct", type=float, default=0.15,
                        help="CL dominance threshold %% (default: 0.15)")
    g_tune.add_argument("--wc-pct", type=float, default=0.15,
                        help="Word-count dominance threshold %% (default: 0.15)")
    g_tune.add_argument("--cl-tol", type=int, default=10,
                        help="Content-length tolerance +/- bytes (default: 10)")
    g_tune.add_argument("--simhash-threshold", type=int, default=10,
                        help="SimHash hamming distance threshold (default: 10)")
    g_tune.add_argument("--min-cluster", type=int, default=5,
                        help="Min cluster size to flag as FP (default: 5)")
    g_tune.add_argument("--reprobe", action="store_true",
                        help="Re-fetch URLs to collect bodies for SimHash (ffuf mode)")

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

        # Optional reprobe
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

        # Cluster analysis
        engine = ClusterFPEngine(
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

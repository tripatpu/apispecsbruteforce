#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffuf_filter.py - Production-grade false-positive filter for ffuf JSON output.

Parses ffuf scan results and aggressively removes noise (soft-404s, redirect
traps, generic error pages, static assets) using baseline detection, status
code filtering, content-length clustering with rarity scoring, and redirect
analysis. Outputs a colorised table, a raw URL list, and clean JSON.

Usage:
    python ffuf_filter.py scan.json
    python ffuf_filter.py scan.json --baseline-length 1234 --threshold 3 --verbose
    python ffuf_filter.py scan.json --keep-status 403,500 --remove-extensions .js,.css
"""

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional colour support - degrades gracefully
# ---------------------------------------------------------------------------
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _Stub:
        """No-op attribute access so Fore.X / Style.X resolve to empty string."""
        def __getattr__(self, _):
            return ""

    Fore = _Stub()
    Style = _Stub()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Status codes considered interesting by default
DEFAULT_KEEP_STATUS = {
    200, 201, 202, 203, 204, 205, 206,          # 2xx success
    300, 301, 302, 303, 307, 308,                # 3xx redirect
    401, 403, 405, 406, 415, 422, 426, 429,      # 4xx auth / method
    500, 502, 503,                                # 5xx server-side
}

# Status codes that are almost always uninteresting
DEFAULT_DROP_STATUS = {400, 404, 410, 501, 505}

# Redirect destinations that indicate a catch-all login/home wall
REDIRECT_TRAP_PATTERNS = re.compile(
    r"(?:^/$"
    r"|/(?:index\.html?|home|default\.aspx?)$"
    r"|/(?:login|log-in|signin|sign-in|sso|auth|oauth|cas/login"
    r"|adfs|saml|openid|connect/authorize)(?:[/?#]|$))",
    re.IGNORECASE,
)

DEFAULT_MIN_SIZE = 50  # bytes - anything smaller is almost certainly noise

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_ffuf_json(path):
    """Read an ffuf JSON file and return the results array."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        sys.exit("[!] File not found: {}".format(path))
    except json.JSONDecodeError as exc:
        sys.exit("[!] Malformed JSON in {}: {}".format(path, exc))

    # ffuf wraps results differently depending on version
    if isinstance(data, dict):
        results = data.get("results", data.get("Results", []))
    elif isinstance(data, list):
        results = data
    else:
        sys.exit("[!] Unexpected JSON structure - expected dict or list at top level.")

    if not results:
        sys.exit("[!] No results found in {}.".format(path))

    return results


def normalise(result):
    """Ensure every result dict has the keys we rely on, with safe defaults."""
    return {
        "url":              result.get("url", result.get("Url", "")),
        "status":           int(result.get("status", result.get("Status", 0))),
        "content_length":   int(result.get("length", result.get("content-length",
                                result.get("content_length", result.get("Content-Length", 0))))),
        "content_words":    int(result.get("words", result.get("content_words",
                                result.get("Words", 0)))),
        "lines":            int(result.get("lines", result.get("Lines", 0))),
        "redirectlocation": result.get("redirectlocation", result.get("RedirectLocation", "")),
        "duration":         result.get("duration", result.get("Duration", 0)),
        "input":            result.get("input", result.get("Input", {})),
        # preserve the original blob for the JSON export
        "_raw":             result,
    }


def compute_baseline(results, user_baseline):
    """
    Determine the content_length that represents the server's default
    'not found' page. This is the single most effective soft-404 killer.

    Strategy:
      1. If the user supplied --baseline-length, trust it.
      2. Otherwise, look at all 404 responses and take the most common length.
      3. If there are no 404s, fall back to the most common length overall.
      4. Only use the auto-detected baseline if it accounts for >=10% of
         applicable responses (avoids clobbering a scan with no dominant
         false-positive length).
    """
    if user_baseline is not None:
        return user_baseline

    # Gather 404 lengths
    lengths_404 = [r["content_length"] for r in results if r["status"] == 404]
    pool = lengths_404 if lengths_404 else [r["content_length"] for r in results]

    if not pool:
        return None

    counter = Counter(pool)
    most_common_len, most_common_count = counter.most_common(1)[0]

    # Sanity gate: only auto-baseline if it covers >=10% of the pool
    if most_common_count / len(pool) < 0.10:
        return None

    return most_common_len


def is_redirect_trap(result):
    """Return True if this redirect points to a generic login/home page."""
    loc = result["redirectlocation"]
    if not loc:
        return False
    # Normalise: strip scheme+host so we compare paths only
    path = re.sub(r"^https?://[^/]+", "", loc)
    return bool(REDIRECT_TRAP_PATTERNS.search(path))


def assign_rarity(results):
    """
    Score each result 1-10 based on how rare its content_length is among
    the surviving set. 1 = unique (most interesting), 10 = most common.
    Uses log-scaled quantile bucketing.
    """
    if not results:
        return results

    counter = Counter(r["content_length"] for r in results)
    freq_values = sorted(set(counter.values()))

    if len(freq_values) <= 1:
        for r in results:
            r["rarity"] = 1
        return results

    # Map each frequency to a 1-10 bucket (1 = rarest)
    max_freq = max(freq_values)
    min_freq = min(freq_values)
    log_min = math.log1p(min_freq)
    log_max = math.log1p(max_freq)
    span = log_max - log_min if log_max != log_min else 1.0

    for r in results:
        freq = counter[r["content_length"]]
        normalised = (math.log1p(freq) - log_min) / span   # 0.0 - 1.0
        r["rarity"] = max(1, min(10, int(normalised * 9) + 1))

    return results


def parse_extensions(raw):
    """Turn '.js,.css,.png' into {'.js', '.css', '.png'}."""
    if not raw:
        return set()
    exts = set()
    for part in raw.split(","):
        part = part.strip()
        if part and not part.startswith("."):
            part = "." + part
        if part:
            exts.add(part.lower())
    return exts


def url_has_extension(url, exts):
    """Return True if the URL path ends with one of the given extensions."""
    path = url.split("?", 1)[0].split("#", 1)[0]
    lower = path.lower()
    return any(lower.endswith(ext) for ext in exts)

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

STATUS_COLOURS = {
    2: Fore.GREEN,
    3: Fore.CYAN,
    4: Fore.YELLOW,
    5: Fore.RED,
}


def colour_status(code):
    colour = STATUS_COLOURS.get(code // 100, "")
    return "{}{}{}".format(colour, code, Style.RESET_ALL)


def rarity_bar(score):
    """Visual bar: lower score = brighter / more markers."""
    filled = 10 - score + 1
    bar = "#" * filled + "." * (score - 1)
    if score <= 3:
        return "{}{}{}".format(Fore.GREEN, bar, Style.RESET_ALL)
    if score <= 6:
        return "{}{}{}".format(Fore.YELLOW, bar, Style.RESET_ALL)
    return "{}{}{}".format(Fore.RED, bar, Style.RESET_ALL)


def print_table(results):
    """Pretty-print results as a table."""
    if not results:
        print("\n{}[*] No results survived filtering.{}".format(Fore.YELLOW, Style.RESET_ALL))
        return

    # Column widths
    max_url = min(max((len(r["url"]) for r in results), default=40), 100)
    hdr_fmt = "  {:<" + str(max_url) + "}  {:>6}  {:>8}  {:>12}  {}"
    row_fmt = hdr_fmt

    sep = "-" * (max_url + 42)
    print("\n{}{}{}".format(Style.BRIGHT, sep, Style.RESET_ALL))
    print(hdr_fmt.format("URL", "Status", "Length", "Rarity", "Redirect"))
    print("{}{}{}".format(Style.BRIGHT, sep, Style.RESET_ALL))

    for r in results:
        redirect = r["redirectlocation"] or ""
        if len(redirect) > 50:
            redirect = redirect[:47] + "..."
        print(row_fmt.format(
            r["url"][:max_url],
            colour_status(r["status"]),
            str(r["content_length"]),
            rarity_bar(r["rarity"]),
            redirect,
        ))

    print("{}{}{}".format(Style.BRIGHT, sep, Style.RESET_ALL))
    print("  {}{}{} result(s) after filtering.\n".format(Fore.GREEN, len(results), Style.RESET_ALL))


def save_urls(results, path):
    with open(path, "w") as fh:
        for r in results:
            fh.write(r["url"] + "\n")
    print("{}[+] Raw URLs saved -> {}{}".format(Fore.CYAN, path, Style.RESET_ALL))


def save_json(results, path):
    export = [r["_raw"] for r in results]
    with open(path, "w") as fh:
        json.dump({"results": export}, fh, indent=2, default=str)
    print("{}[+] Filtered JSON saved -> {}{}".format(Fore.CYAN, path, Style.RESET_ALL))

# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def filter_results(
    results,
    baseline=None,
    keep_status=None,
    min_size=DEFAULT_MIN_SIZE,
    threshold=10,
    remove_exts=None,
    verbose=False,
):
    """Run every filter stage and return surviving results."""

    if keep_status is None:
        keep_status = DEFAULT_KEEP_STATUS
    if remove_exts is None:
        remove_exts = set()

    kept = []
    drop_reasons = Counter()

    for r in results:
        reason = None

        # --- 1. Baseline soft-404 ---
        if baseline is not None and r["content_length"] == baseline:
            reason = "baseline length ({})".format(baseline)

        # --- 2. Status code ---
        elif r["status"] not in keep_status:
            reason = "status {}".format(r["status"])

        # --- 3. Redirect trap ---
        elif r["status"] in {301, 302, 303, 307, 308} and is_redirect_trap(r):
            reason = "redirect trap -> {}".format(r["redirectlocation"])

        # --- 4. Minimum content size (skip 204 and 3xx - legitimately empty) ---
        elif r["content_length"] < min_size and r["status"] != 204 and r["status"] // 100 != 3:
            reason = "too small ({} < {})".format(r["content_length"], min_size)

        # --- 5. Static asset extension ---
        elif remove_exts and url_has_extension(r["url"], remove_exts):
            reason = "static asset extension"

        if reason:
            drop_reasons[reason] += 1
            if verbose:
                print("  {}[-]{} DROP {}  <- {}".format(Fore.RED, Style.RESET_ALL, r["url"], reason))
        else:
            kept.append(r)

    # --- 6. Rarity scoring ---
    kept = assign_rarity(kept)

    # --- 7. Threshold filter ---
    if threshold < 10:
        before = len(kept)
        kept = [r for r in kept if r["rarity"] <= threshold]
        trimmed = before - len(kept)
        if trimmed and verbose:
            print("  {}[~] Threshold {} removed {} common-length result(s).{}".format(
                Fore.YELLOW, threshold, trimmed, Style.RESET_ALL))
        drop_reasons["rarity > {}".format(threshold)] += trimmed

    # --- Summary ---
    if verbose and drop_reasons:
        print("\n{}Drop summary:{}".format(Style.BRIGHT, Style.RESET_ALL))
        for reason, count in drop_reasons.most_common():
            print("  {:>6}  {}".format(count, reason))

    return kept

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="Filter ffuf JSON output to remove false positives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python ffuf_filter.py scan.json\n"
            "  python ffuf_filter.py scan.json --baseline-length 1234 --threshold 3 --verbose\n"
            "  python ffuf_filter.py scan.json --keep-status 403,500 --remove-extensions .js,.css\n"
        ),
    )
    p.add_argument("input", help="Path to ffuf JSON output file")
    p.add_argument(
        "--baseline-length", type=int, default=None, metavar="N",
        help="Manually set the soft-404 content_length baseline. Auto-detected if omitted.",
    )
    p.add_argument(
        "--keep-status", type=str, default=None, metavar="CODES",
        help="Comma-separated status codes to keep (overrides defaults).",
    )
    p.add_argument(
        "--min-size", type=int, default=DEFAULT_MIN_SIZE, metavar="N",
        help="Drop responses smaller than N bytes (default {}).".format(DEFAULT_MIN_SIZE),
    )
    p.add_argument(
        "--threshold", type=int, default=10, choices=range(1, 11), metavar="1-10",
        help="Keep only results with rarity score <= this value (1 = rarest only, 10 = all).",
    )
    p.add_argument(
        "--remove-extensions", type=str, default=None, metavar="EXTS",
        help="Comma-separated extensions to drop (e.g. .js,.css,.png).",
    )
    p.add_argument(
        "--output-urls", type=str, default="filtered_urls.txt", metavar="FILE",
        help="Path for the raw URL list output (default filtered_urls.txt).",
    )
    p.add_argument(
        "--output-json", type=str, default="filtered_output.json", metavar="FILE",
        help="Path for the filtered JSON output (default filtered_output.json).",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print every dropped result with its reason.",
    )
    p.add_argument(
        "--sort", type=str, default="rarity",
        choices=["rarity", "status", "length", "url"],
        help="Sort output by this field (default rarity).",
    )
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # -- Load & normalise --
    print("\n{}[*] Loading {}...{}".format(Fore.CYAN, args.input, Style.RESET_ALL))
    raw = load_ffuf_json(args.input)
    results = [normalise(r) for r in raw]
    print("    {} total result(s) loaded.".format(len(results)))

    # -- Resolve keep-status set --
    if args.keep_status:
        keep_status = {int(c.strip()) for c in args.keep_status.split(",")}
    else:
        keep_status = DEFAULT_KEEP_STATUS

    # -- Baseline detection --
    baseline = compute_baseline(results, args.baseline_length)
    if baseline is not None:
        bl_count = sum(1 for r in results if r["content_length"] == baseline)
        src = "user-supplied" if args.baseline_length is not None else "auto-detected"
        print("    Baseline length: {}{}{} ({}, matches {} result(s))".format(
            Fore.YELLOW, baseline, Style.RESET_ALL, src, bl_count))
    else:
        print("    {}No dominant baseline detected - skipping soft-404 filter.{}".format(
            Fore.YELLOW, Style.RESET_ALL))

    # -- Extensions --
    remove_exts = parse_extensions(args.remove_extensions)

    # -- Run filters --
    print("\n{}[*] Filtering...{}".format(Fore.CYAN, Style.RESET_ALL))
    kept = filter_results(
        results,
        baseline=baseline,
        keep_status=keep_status,
        min_size=args.min_size,
        threshold=args.threshold,
        remove_exts=remove_exts,
        verbose=args.verbose,
    )

    # -- Sort --
    sort_key = {
        "rarity":  lambda r: (r["rarity"], r["content_length"], r["url"]),
        "status":  lambda r: (r["status"], r["rarity"], r["url"]),
        "length":  lambda r: (r["content_length"], r["rarity"], r["url"]),
        "url":     lambda r: r["url"],
    }[args.sort]
    kept.sort(key=sort_key)

    # -- Output --
    print_table(kept)
    if kept:
        save_urls(kept, args.output_urls)
        save_json(kept, args.output_json)
    else:
        print("{}[!] Nothing to write - all results filtered out.{}".format(
            Fore.YELLOW, Style.RESET_ALL))
        print("    Try raising --threshold or lowering --min-size.\n")


if __name__ == "__main__":
    main()

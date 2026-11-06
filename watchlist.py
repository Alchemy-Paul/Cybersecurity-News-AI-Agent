"""Match stories and vulnerabilities against the products your organisation runs.

The watchlist is a plain text file, one term per line (``#`` starts a comment):

    fortinet
    microsoft exchange
    citrix netscaler

Prefer specific terms. A bare word like "exchange" will match a lot of noise.
Matching ignores case and punctuation and only matches whole words.
"""

import re
from pathlib import Path


def _normalise(text):
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def load_watchlist(path):
    """Return a list of normalised terms, or [] if the file is missing."""
    if not path:
        return []
    file_path = Path(path)
    if not file_path.is_file():
        return []
    terms = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        term = _normalise(line)
        if term and term not in terms:
            terms.append(term)
    return terms


def match_watchlist(terms, texts=(), vendors_products=()):
    """Return the watchlist terms found in the free text or vendor/product names."""
    if not terms:
        return []
    haystack = " | ".join(_normalise(t) for t in list(texts) + list(vendors_products) if t)
    haystack = f" {haystack} "
    hits = []
    for term in terms:
        if re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", haystack):
            hits.append(term)
    return hits

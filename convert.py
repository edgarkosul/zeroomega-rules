import re
from pathlib import Path
from urllib.request import Request, urlopen

SOURCE = (
    "https://raw.githubusercontent.com/"
    "haritos90/allow-domains/main/Russia/russia-all.lst"
)

request = Request(SOURCE, headers={"User-Agent": "zeroomega-rules"})
with urlopen(request, timeout=60) as response:
    source = response.read().decode("utf-8-sig")

domains = set()

for number, line in enumerate(source.splitlines(), start=1):
    domain = line.strip().lower()

    if not domain or domain.startswith(("#", "!")):
        continue

    # .ua -> ua; *.example.com -> example.com
    if domain.startswith("*."):
        domain = domain[2:]
    domain = domain.lstrip(".").rstrip(".")
    domain = domain.encode("idna").decode("ascii")

    labels = domain.split(".")
    if len(domain) > 253 or any(
        not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
        for label in labels
    ):
        raise ValueError(f"Unexpected entry on line {number}: {line!r}")

    domains.add(domain)

if not domains:
    raise RuntimeError("Source list is empty; existing file was not changed")

# ZeroOmega: ||example.com matches the domain and its subdomains.
# Do not append ^: ZeroOmega's AutoProxy parser treats it literally.
result = "\n".join([
    "[AutoProxy 0.2.9]",
    f"! Source: {SOURCE}",
    "! Generated automatically. Do not edit.",
    *[f"||{domain}" for domain in sorted(domains)],
    "",
])

Path("zeroomega.txt").write_text(result, encoding="utf-8")
print(f"Generated zeroomega.txt: {len(domains)} rules")

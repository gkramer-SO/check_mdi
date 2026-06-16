#!/usr/bin/env python3

"""
Enumerate likely Microsoft Defender for Identity workspace endpoints and validate
them with DNS plus the documented MDI sensor API ping path.
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from typing import Iterable

import dns.exception
import dns.resolver
import httpx


AUTODISCOVER_URL = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
PING_PATH = "/tri/sensor/api/ping"
VERSION_RE = re.compile(r"^\s*\"?\d+\.\d+\.\d+\.\d+\"?\s*$")
MAX_BODY_SAMPLE = 120
MAX_CANDIDATES_DEFAULT = 25


@dataclass
class DnsAnswer:
    record_type: str
    value: str
    ttl: int | None = None


@dataclass
class CheckResult:
    candidate: str
    fqdn: str
    ping_url: str
    dns_status: str
    dns_answers: list[DnsAnswer]
    http_status: int | None
    body_sample: str | None
    classification: str
    confidence: str
    error: str | None = None


def build_autodiscover_body(domain: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
    xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Header>
    <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
    <a:MessageID>urn:uuid:6389558d-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
    <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand="1">https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc</a:To>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Request>
        <Domain>{domain}</Domain>
      </Request>
    </GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>"""


def parse_autodiscover_domains(xml_text: str) -> list[str]:
    tree = ET.fromstring(xml_text)
    domains: list[str] = []
    for elem in tree.iter():
        if elem.tag == "{http://schemas.microsoft.com/exchange/2010/Autodiscover}Domain" and elem.text:
            domains.append(elem.text.strip().lower())
    return dedupe(domains)


def discover_domains(domain: str, timeout: float) -> list[str]:
    headers = {
        "Content-type": "text/xml; charset=utf-8",
        "User-agent": "AutodiscoverClient",
    }
    response = httpx.post(
        AUTODISCOVER_URL,
        content=build_autodiscover_body(domain),
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()
    return parse_autodiscover_domains(response.text)


def normalize_candidate(value: str) -> str | None:
    candidate = value.strip().lower()
    candidate = re.sub(r"^https?://", "", candidate)
    candidate = candidate.split("/", 1)[0]
    if candidate.endswith("sensorapi.atp.azure.com"):
        candidate = candidate[: -len("sensorapi.atp.azure.com")]
    if candidate.endswith("sensorapi.gcc.atp.azure.com"):
        candidate = candidate[: -len("sensorapi.gcc.atp.azure.com")]
    candidate = candidate.strip(".-_")
    if not candidate:
        return None
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}", candidate):
        return None
    return candidate


def domain_root(domain: str) -> str:
    labels = domain.strip().lower().split(".")
    if len(labels) >= 2:
        return labels[-2]
    return labels[0]


def tenant_candidates(domains: Iterable[str]) -> list[str]:
    candidates = []
    for domain in domains:
        labels = domain.lower().split(".")
        if len(labels) >= 3 and labels[-2:] == ["onmicrosoft", "com"]:
            candidates.append(labels[0])
    return dedupe(candidates)


def generate_candidates(
    input_domain: str,
    discovered_domains: Iterable[str],
    manual_candidates: Iterable[str],
    max_candidates: int = MAX_CANDIDATES_DEFAULT,
) -> list[str]:
    raw_candidates: list[str] = []
    discovered = list(discovered_domains)
    raw_candidates.extend(tenant_candidates(discovered))

    for domain in [input_domain, *discovered]:
        root = domain_root(domain)
        raw_candidates.extend([root, root.replace("-", ""), root.replace(".", "")])

    raw_candidates.extend(manual_candidates)
    normalized = [candidate for item in raw_candidates if (candidate := normalize_candidate(item))]
    return dedupe(normalized)[:max_candidates]


def endpoint_suffix(cloud: str) -> str:
    if cloud == "commercial":
        return "sensorapi.atp.azure.com"
    if cloud == "gcc":
        return "sensorapi.gcc.atp.azure.com"
    raise ValueError(f"Unsupported cloud: {cloud}")


def endpoint_for_candidate(candidate: str, cloud: str) -> tuple[str, str]:
    fqdn = f"{candidate}{endpoint_suffix(cloud)}"
    return fqdn, f"https://{fqdn}{PING_PATH}"


def make_resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def resolve_endpoint(fqdn: str, resolver: dns.resolver.Resolver) -> tuple[str, list[DnsAnswer], str | None]:
    answers: list[DnsAnswer] = []
    errors: list[str] = []

    for record_type in ("CNAME", "A", "AAAA"):
        try:
            result = resolver.resolve(fqdn, record_type)
            ttl = getattr(getattr(result, "rrset", None), "ttl", None)
            for item in result:
                value = item.target.to_text().rstrip(".") if record_type == "CNAME" else item.to_text()
                answers.append(DnsAnswer(record_type=record_type, value=value, ttl=ttl))
        except dns.resolver.NXDOMAIN:
            return "nxdomain", [], "NXDOMAIN"
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.Timeout:
            errors.append(f"{record_type}: timeout")
        except dns.exception.DNSException as exc:
            errors.append(f"{record_type}: {exc.__class__.__name__}")

    if answers:
        return "resolved", answers, None
    if errors:
        return "error", answers, "; ".join(errors)
    return "no_answer", answers, "No DNS answers"


def safe_body_sample(text: str | None) -> str | None:
    if text is None:
        return None
    return text.replace("\r", "\\r").replace("\n", "\\n")[:MAX_BODY_SAMPLE]


def classify(dns_status: str, http_status: int | None, body_sample: str | None, error: str | None) -> tuple[str, str]:
    if dns_status == "nxdomain":
        return "not_found", "low"
    if dns_status != "resolved":
        return "inconclusive", "low"
    if http_status == 200 and body_sample and VERSION_RE.match(body_sample):
        return "confirmed_reachable", "high"
    if http_status == 503:
        return "reachable_but_unhealthy_or_legacy", "medium"
    if http_status is not None:
        return "endpoint_exists_inconclusive", "medium"
    if error:
        return "dns_only", "low"
    return "dns_only", "low"


def check_candidate(
    candidate: str,
    cloud: str,
    resolver: dns.resolver.Resolver,
    http_timeout: float,
) -> CheckResult:
    fqdn, ping_url = endpoint_for_candidate(candidate, cloud)
    dns_status, dns_answers, dns_error = resolve_endpoint(fqdn, resolver)
    http_status = None
    body_sample = None
    error = dns_error

    if dns_status == "resolved":
        try:
            response = httpx.get(ping_url, timeout=http_timeout, follow_redirects=False)
            http_status = response.status_code
            body_sample = safe_body_sample(response.text)
            error = None
        except httpx.HTTPError as exc:
            error = exc.__class__.__name__

    classification, confidence = classify(dns_status, http_status, body_sample, error)
    return CheckResult(
        candidate=candidate,
        fqdn=fqdn,
        ping_url=ping_url,
        dns_status=dns_status,
        dns_answers=dns_answers,
        http_status=http_status,
        body_sample=body_sample,
        classification=classification,
        confidence=confidence,
        error=error,
    )


def dedupe(values: Iterable[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def read_candidates_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#")]


def result_to_dict(result: CheckResult) -> dict:
    return asdict(result)


def print_human(
    input_domain: str,
    discovered_domains: list[str],
    candidates: list[str],
    results: list[CheckResult],
) -> None:
    print(f"[+] Input domain: {input_domain}")
    print("\n[+] Domains discovered:")
    if discovered_domains:
        print(*discovered_domains, sep="\n")
    else:
        print("(none)")

    print("\n[+] Candidate workspace names:")
    print(*candidates, sep="\n")

    print("\n[+] Results:")
    for result in results:
        label = result.classification.upper()
        status = f"HTTP {result.http_status}" if result.http_status is not None else result.dns_status.upper()
        line = f"{label} {result.fqdn} {status} confidence={result.confidence}"
        print(line)
        if result.body_sample:
            print(f"  body={result.body_sample}")
        if result.error:
            print(f"  error={result.error}")

    if any(result.classification == "confirmed_reachable" for result in results):
        print("\nResult: confirmed reachable MDI sensor API endpoint found.")
    else:
        print("\nResult: no confirmed MDI endpoint found for tested candidates.")
        print("Note: this does not prove MDI is absent. The workspace name may differ from tested candidates.")


def run(args: argparse.Namespace) -> int:
    manual_candidates = list(args.candidate or [])
    if args.candidates_file:
        manual_candidates.extend(read_candidates_file(args.candidates_file))

    try:
        discovered_domains = discover_domains(args.domain, args.http_timeout)
    except Exception as exc:
        discovered_domains = []
        discover_error = exc.__class__.__name__
    else:
        discover_error = None

    candidates = generate_candidates(
        input_domain=args.domain,
        discovered_domains=discovered_domains,
        manual_candidates=manual_candidates,
        max_candidates=args.max_candidates,
    )
    resolver = make_resolver(args.dns_timeout)
    results = [check_candidate(candidate, args.cloud, resolver, args.http_timeout) for candidate in candidates]

    payload = {
        "input_domain": args.domain,
        "cloud": args.cloud,
        "domains_discovered": discovered_domains,
        "tenant_candidates": tenant_candidates(discovered_domains),
        "discovery_error": discover_error,
        "results": [result_to_dict(result) for result in results],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        if discover_error:
            print(f"[!] Autodiscover failed: {discover_error}")
        print_human(args.domain, discovered_domains, candidates, results)

    return 0 if any(result.classification == "confirmed_reachable" for result in results) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enumerate likely MDI workspace endpoints and validate the sensor API ping endpoint."
    )
    parser.add_argument("-d", "--domain", required=True, help="Input domain, for example: example.com")
    parser.add_argument("--candidate", action="append", help="Additional workspace candidate. May be repeated.")
    parser.add_argument("--candidates-file", help="Newline-delimited workspace candidate file.")
    parser.add_argument("--cloud", choices=("commercial", "gcc"), default="commercial")
    parser.add_argument("--http-timeout", type=float, default=5.0)
    parser.add_argument("--dns-timeout", type=float, default=3.0)
    parser.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES_DEFAULT)
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser


def main() -> int:
    return run(build_parser().parse_args())


if __name__ == "__main__":
    sys.exit(main())

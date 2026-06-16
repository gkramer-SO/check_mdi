import dns.resolver
import httpx
import pytest

import check_mdi


AUTODISCOVER_XML = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <GetFederationInformationResponseMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Response>
        <Domains>
          <Domain>example.com</Domain>
          <Domain>example.onmicrosoft.com</Domain>
        </Domains>
      </Response>
    </GetFederationInformationResponseMessage>
  </s:Body>
</s:Envelope>"""


def test_parse_autodiscover_domains():
    assert check_mdi.parse_autodiscover_domains(AUTODISCOVER_XML) == [
        "example.com",
        "example.onmicrosoft.com",
    ]


def test_tenant_candidates_extract_onmicrosoft_prefixes():
    assert check_mdi.tenant_candidates(["example.com", "tenant.onmicrosoft.com"]) == ["tenant"]


def test_generate_candidates_includes_cisco_domain_root():
    candidates = check_mdi.generate_candidates("cisco.com", ["cisco.com"], [], max_candidates=25)
    assert "cisco" in candidates


def test_generate_candidates_deduplicates_and_normalizes_manual_values():
    candidates = check_mdi.generate_candidates(
        "example.com",
        ["tenant.onmicrosoft.com"],
        ["https://TenantSensorapi.atp.azure.com/tri/sensor/api/ping", "tenant"],
        max_candidates=25,
    )
    assert candidates.count("tenant") == 1


def test_endpoint_generation_commercial_and_gcc():
    assert check_mdi.endpoint_for_candidate("contoso", "commercial") == (
        "contososensorapi.atp.azure.com",
        "https://contososensorapi.atp.azure.com/tri/sensor/api/ping",
    )
    assert check_mdi.endpoint_for_candidate("contoso", "gcc") == (
        "contososensorapi.gcc.atp.azure.com",
        "https://contososensorapi.gcc.atp.azure.com/tri/sensor/api/ping",
    )


@pytest.mark.parametrize(
    "dns_status,http_status,body,error,expected",
    [
        ("resolved", 200, "2.255.19267.9636", None, ("confirmed_reachable", "high")),
        ("resolved", 503, "Service unavailable", None, ("reachable_but_unhealthy_or_legacy", "medium")),
        ("resolved", 404, "Not found", None, ("endpoint_exists_inconclusive", "medium")),
        ("resolved", None, None, "ConnectTimeout", ("dns_only", "low")),
        ("nxdomain", None, None, "NXDOMAIN", ("not_found", "low")),
        ("error", None, None, "timeout", ("inconclusive", "low")),
    ],
)
def test_classify(dns_status, http_status, body, error, expected):
    assert check_mdi.classify(dns_status, http_status, body, error) == expected


def test_check_candidate_confirmed_reachable(monkeypatch):
    monkeypatch.setattr(
        check_mdi,
        "resolve_endpoint",
        lambda fqdn, resolver: (
            "resolved",
            [check_mdi.DnsAnswer(record_type="A", value="203.0.113.10", ttl=60)],
            None,
        ),
    )
    monkeypatch.setattr(
        check_mdi.httpx,
        "get",
        lambda *args, **kwargs: httpx.Response(200, text="2.255.19267.9636"),
    )

    result = check_mdi.check_candidate("cisco", "commercial", dns.resolver.Resolver(), 5)

    assert result.fqdn == "ciscosensorapi.atp.azure.com"
    assert result.http_status == 200
    assert result.classification == "confirmed_reachable"
    assert result.confidence == "high"


def test_check_candidate_nxdomain(monkeypatch):
    monkeypatch.setattr(
        check_mdi,
        "resolve_endpoint",
        lambda fqdn, resolver: ("nxdomain", [], "NXDOMAIN"),
    )

    result = check_mdi.check_candidate("missing", "commercial", dns.resolver.Resolver(), 5)

    assert result.classification == "not_found"
    assert result.http_status is None

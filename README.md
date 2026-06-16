# check_mdi

`check_mdi.py` enumerates likely Microsoft Defender for Identity (MDI) workspace names and checks whether the public sensor API endpoint is reachable.

The tool preserves the original Microsoft 365 Autodiscover domain enumeration flow, then validates candidates with DNS and the documented HTTPS ping endpoint:

```text
https://<workspace_name>sensorapi.atp.azure.com/tri/sensor/api/ping
```

Microsoft documents that a successful connectivity test returns the latest sensor version number.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python check_mdi.py -d example.com
python check_mdi.py -d example.com --candidate examplecorp
python check_mdi.py -d example.com --candidates-file candidates.txt
python check_mdi.py -d example.com --cloud commercial
python check_mdi.py -d example.com --cloud gcc
python check_mdi.py -d example.com --http-timeout 5 --dns-timeout 3
python check_mdi.py -d example.com --json
```

## Findings

- `confirmed_reachable`: DNS resolved and HTTPS ping returned HTTP 200 with a version-like body.
- `reachable_but_unhealthy_or_legacy`: DNS resolved and HTTPS ping returned HTTP 503.
- `endpoint_exists_inconclusive`: DNS resolved and HTTPS reached the endpoint, but the response was not a documented success shape.
- `dns_only`: hostname resolved, but HTTP validation failed or was inconclusive.
- `not_found`: DNS returned NXDOMAIN for the tested candidate.
- `inconclusive`: DNS, timeout, proxy, TLS, or network behavior prevented a clear result.

## JSON Output

```json
{
  "input_domain": "example.com",
  "cloud": "commercial",
  "domains_discovered": [],
  "tenant_candidates": [],
  "discovery_error": null,
  "results": [
    {
      "candidate": "example",
      "fqdn": "examplesensorapi.atp.azure.com",
      "ping_url": "https://examplesensorapi.atp.azure.com/tri/sensor/api/ping",
      "dns_status": "resolved",
      "dns_answers": [],
      "http_status": 200,
      "body_sample": "2.255.19267.9636",
      "classification": "confirmed_reachable",
      "confidence": "high",
      "error": null
    }
  ]
}
```

## Important Limitations

A positive result confirms that a candidate Defender for Identity sensor API endpoint is reachable. It does not prove sensor deployment coverage, domain controller onboarding, alerting health, licensing state, or tenant ownership by itself.

A negative result for a guessed candidate does not prove MDI is absent. It may only mean the tested workspace name was incorrect.

Use this tool only for authorized security testing.

## Tests

```bash
pytest
```

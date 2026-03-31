# 80211 Testing Framework

A capability-aware WiFi test framework for OpenWiFi APs.

## Key Design Principles

- **Core is immutable** — adding a new test means adding one new script in `tests/`. Nothing in `framework/` changes.
- **Capability-aware** — hardware is inventoried at session start; tests that can't run on available hardware are automatically skipped with a clear reason.
- **Traffic engine abstraction** — tests don't know if they're running on LANforge or RPi5+iperf3. Both implement the same interface.
- **External infrastructure** — DHCP, VLAN, and RADIUS are managed on a dedicated Linux box over SSH. No LANforge NAT.
- **Allure reporting** — every test attaches AP config, traffic results, and AP logs to a rich HTML report.

## Supported Hardware

| Hardware | STA Capacity | Best For |
|---|---|---|
| LANforge + MT7915 | 19 STAs/radio | Capacity tests |
| LANforge + BE200 | 1 STA/radio (1:1) | Performance / WiFi 7 tests |
| RPi5 + BE200 | 1 STA/RPi5 | Rate limiting, basic connectivity |

## Project Structure

```
80211_testing_framework/
├── config/                    # Testbed descriptors (gitignored — contains credentials)
│   └── profiles/              # Example profiles for different lab setups
├── framework/                 # Core — never modified when adding tests
│   ├── clients/               # uCentral, AP, LANforge, infra SSH clients
│   ├── traffic/               # TrafficEngine ABC + LANforge / RPi5 implementations
│   ├── infra/                 # DHCP, RADIUS, VLAN, iptables managers
│   ├── ap/                    # AP controller + uCentral config builder
│   ├── capability/            # Hardware inventory and capability registry
│   └── reporting/             # Allure helpers + environment.properties
├── tests/                     # Test scripts — one file per test case
│   ├── connectivity/
│   ├── capacity/
│   ├── performance/
│   ├── rate_limiting/
│   ├── enterprise/
│   └── multi_vlan/
├── conftest.py                # Root pytest fixtures and capability skip hook
└── pytest.ini                 # Markers, allure config, default args
```

## Quickstart

### 1. Install dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Configure your testbed
```bash
cp config/profiles/example_lanforge.yaml config/testbed.yaml
# Edit config/testbed.yaml with your lab IPs and credentials
```

### 3. Run tests
```bash
# Run all rate limiting tests
pytest -m "rate_limiting" -v -s --testbed-config config/testbed.yaml

# Run a single test
pytest tests/rate_limiting/test_wpa2_br_downstream_10mbps_5g.py -v -s

# Run with allure report
pytest -m "rate_limiting" --alluredir allure-results
allure serve allure-results
```

## Adding a New Test

1. Pick the right subdirectory under `tests/`
2. Create a new `.py` file named `test_{security}_{mode}_{metric}_{band}.py`
3. Copy the template from `tests/_template.py`
4. Fill in allure metadata, markers, AP config, and assertions
5. Done — zero framework files modified

## Capability Markers

| Marker | Requirement |
|---|---|
| `@requires_two_endpoints` | Any traffic setup (LANforge or RPi5) |
| `@requires_multi_sta` | MT7915 or multi-STA capable radio |
| `@requires_wifi7` | BE200 or WiFi 7 capable radio |
| `@requires_sixghz` | 6 GHz radio available |
| `@requires_radius` | FreeRADIUS on infra box |
| `@requires_vlan` | VLAN-capable infra |
| `@requires_min_stations(n)` | At least n total STA capacity |

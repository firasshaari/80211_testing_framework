SHELL := /bin/bash
PY    := .venv/bin/python
PIP   := .venv/bin/pip
CONFIG ?= config/testbed.yaml

UPSTREAM_REPO   ?= Telecominfraproject/wlan-ap
UPSTREAM_BRANCH ?= main
UPSTREAM_PATH   := feeds/ucentral/ucentral-schema/files/etc/ucentral/examples
EXAMPLES_DIR    := configs/examples/upstream

.PHONY: help venv install setup check plan test regression sweep report serve watch infra-up infra-down sync-examples clean

help:
	@echo "make install         Create .venv and install the framework"
	@echo "make setup           Interactive: ask for AP, station, VLANs, RADIUS -> $(CONFIG)"
	@echo "make check           Offline checks — no hardware needed"
	@echo "make plan            Probe the AP + station, list which tests are feasible"
	@echo "make regression      Full sweep against CONFIG=$(CONFIG)"
	@echo "make sweep AREA=x    Only one feature area (security, network_mode, ...)"
	@echo "make watch           Follow a running sweep live (tail progress.log)"
	@echo "make infra-up        Start RADIUS + iperf3 containers on the station host"
	@echo "make infra-down      Stop them"
	@echo "make report          Build and open the Allure report"
	@echo "make sync-examples   Re-vendor examples from $(UPSTREAM_REPO)@$(UPSTREAM_BRANCH)"

# Step 1 of the workflow: log in, stop the uCentral agent, read capabilities,
# and show which examples this bench can actually run. Applies nothing.
plan:
	$(PY) -m framework.plan --testbed-config $(CONFIG)

venv:
	@test -d .venv || python3 -m venv .venv

install: venv
	$(PIP) install -q -e ".[dev]"
	@echo "Installed. Copy config/profiles/example_minimal.yaml to $(CONFIG) next."

# Interactive interview: asks what the bench has (VLAN IDs the DHCP server
# serves, RADIUS address/secret/credentials, iperf peer, ...) and writes CONFIG.
setup:
	$(PY) -m framework.setup $(CONFIG)

# Runs without an AP or a station — validates the corpus, catalog and normalizer.
check:
	$(PY) -m pytest tests/unit -q

regression:
	$(PY) -m pytest tests/regression --testbed-config $(CONFIG) \
		--alluredir $(ALLURE_RESULTS) --clean-alluredir

sweep:
	@test -n "$(AREA)" || { echo "Usage: make sweep AREA=security"; exit 1; }
	$(PY) -m pytest tests/regression -m $(AREA) --testbed-config $(CONFIG) \
		--alluredir $(ALLURE_RESULTS) --clean-alluredir

ALLURE_RESULTS ?= allure-results
ALLURE_REPORT  ?= allure-report

# Allure reports fetch their data over XHR, which file:// blocks, so the report
# must be served rather than opened from disk. `--single-file` would avoid that
# but is broken in allure 2.44 — it emits a shell with no data in it.
report:
	@command -v allure >/dev/null || { echo "allure CLI not found — brew install allure"; exit 1; }
	allure generate $(ALLURE_RESULTS) -o $(ALLURE_REPORT) --clean
	@echo "opening $(ALLURE_REPORT) on a local server (ctrl-c to stop)"
	allure open $(ALLURE_REPORT)

# Generate and serve in one step, without keeping the generated directory.
serve:
	@command -v allure >/dev/null || { echo "allure CLI not found — brew install allure"; exit 1; }
	allure serve $(ALLURE_RESULTS)

# Re-download the upstream examples. Review the diff before committing: upstream
# ships configs that need normalizing (country CA, 80 MHz on 2.4 GHz, channels
# outside their declared band), and 'make check' asserts those rules still hold.
sync-examples:
	@mkdir -p $(EXAMPLES_DIR)
	@curl -sf "https://api.github.com/repos/$(UPSTREAM_REPO)/contents/$(UPSTREAM_PATH)?ref=$(UPSTREAM_BRANCH)" \
	  | $(PY) -c "import json,sys,urllib.request,pathlib; \
d=json.load(sys.stdin); \
out=pathlib.Path('$(EXAMPLES_DIR)'); \
n=[urllib.request.urlretrieve(f['download_url'], out/f['name']) for f in d if f['name'].endswith('.json')]; \
print(f'vendored {len(n)} examples from $(UPSTREAM_BRANCH)')"
	@$(MAKE) --no-print-directory check

clean:
	rm -rf .pytest_cache allure-results allure-report
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

# Follow a running sweep live from another terminal.
watch:
	@touch reports/progress.log && tail -f reports/progress.log

# Self-contained lab services (RADIUS, iperf3) on the station host. See
# infra/README.md — they run on their own macvlan address so station traffic
# has to cross the air to reach them.
STA_HOST ?= $(shell $(PY) -c "from framework.config import load_testbed_config as l; print(l('$(CONFIG)').station.host)" 2>/dev/null)
STA_USER ?= $(shell $(PY) -c "from framework.config import load_testbed_config as l; print(l('$(CONFIG)').station.user)" 2>/dev/null)

infra-up:
	@test -f infra/infra.env || { echo "Copy infra/infra.env.example to infra/infra.env first"; exit 1; }
	$(PY) -m framework.infra_deploy --testbed-config $(CONFIG) up

infra-down:
	$(PY) -m framework.infra_deploy --testbed-config $(CONFIG) down

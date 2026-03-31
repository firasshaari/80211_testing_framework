"""
Root conftest — session fixtures and capability-based skip hook.
CORE FILE — do not modify when adding new tests.
"""
from __future__ import annotations
import logging
import pytest

from framework.config                    import load_testbed_config, TestbedConfig
from framework.capability.registry       import CapabilityRegistry
from framework.capability.models         import TestbedCapabilities
from framework.clients.controller_client import ControllerClient
from framework.clients.ap_client         import APClient
from framework.ap.ap_controller          import APController
from framework.reporting.allure_helper   import attach_testbed_capabilities
from framework.reporting.environment     import write_environment_properties


def pytest_addoption(parser):
    parser.addoption(
        "--testbed-config",
        default="config/testbed.yaml",
        help="Path to testbed YAML configuration file",
    )


# ── Config ────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def testbed_config(pytestconfig) -> TestbedConfig:
    path = pytestconfig.getoption("--testbed-config")
    return load_testbed_config(path)


# ── Capability Discovery ───────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def testbed_capabilities(testbed_config) -> TestbedCapabilities:
    registry = CapabilityRegistry(testbed_config)
    caps = registry.probe()
    pytest.current_capabilities = caps
    attach_testbed_capabilities(caps)
    logging.info(
        f"Testbed: engine={caps.best_engine}  radios={len(caps.radios)}"
        f"  total_sta={caps.total_sta_capacity}  radius={caps.has_radius}"
    )
    return caps


# ── Capability Skip Hook ──────────────────────────────────────────────────────

def pytest_runtest_setup(item):
    caps: TestbedCapabilities | None = getattr(pytest, "current_capabilities", None)
    if caps is None:
        return

    def skip_if(condition: bool, reason: str):
        if condition:
            pytest.skip(reason)

    for marker in item.iter_markers():
        match marker.name:
            case "requires_lanforge":
                skip_if(not caps.has_lanforge,
                        "LANforge not available in testbed")
            case "requires_rpi5":
                skip_if(not caps.has_rpi5,
                        "No RPi5 hosts configured in testbed")
            case "requires_two_endpoints":
                skip_if(not caps.has_lanforge and not caps.has_rpi5,
                        "No traffic endpoints available (need LANforge or RPi5)")
            case "requires_multi_sta":
                skip_if(not caps.has_multi_sta_radio,
                        "No multi-STA radio (e.g. MT7915) found in testbed")
            case "requires_wifi7":
                skip_if(not caps.has_wifi7_radio,
                        "No WiFi 7 radio (e.g. BE200) found in testbed")
            case "requires_sixghz":
                skip_if(not caps.has_sixghz_radio,
                        "No 6 GHz capable radio in testbed")
            case "requires_radius":
                skip_if(not caps.has_radius,
                        "FreeRADIUS not available on infra box")
            case "requires_vlan":
                skip_if(not caps.has_vlan_infra,
                        "VLAN infra not configured in testbed")
            case "requires_min_stations":
                n = marker.args[0] if marker.args else 1
                skip_if(caps.total_sta_capacity < n,
                        f"Need {n} STAs; testbed capacity is {caps.total_sta_capacity}")


# ── Clients ────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def controller_client(testbed_config) -> ControllerClient:
    return ControllerClient(
        base_url=testbed_config.controller.base_url,
        username=testbed_config.controller.username,
        password=testbed_config.controller.password,
        verify_ssl=testbed_config.controller.verify_ssl,
    )


@pytest.fixture(scope="session")
def ap_client(testbed_config) -> APClient:
    lf = testbed_config.lanforge
    client = APClient(
        serial=testbed_config.ap.serial,
        gateway_host=lf.host if lf else None,
        serial_port=testbed_config.ap.serial_port,
    )
    yield client
    client.close()


# ── Traffic Engine ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def traffic_engine(testbed_capabilities, testbed_config):
    registry = CapabilityRegistry(testbed_config)
    engine = registry.select_traffic_engine(testbed_capabilities)
    if engine is None:
        pytest.skip("No traffic engine available in testbed")
    yield engine
    engine.teardown()


# ── AP Controller ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def ap(controller_client, ap_client, testbed_config) -> APController:
    return APController(
        controller=controller_client,
        ap=ap_client,
        serial=testbed_config.ap.serial,
    )


# ── Allure Environment ────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def allure_environment(testbed_config, testbed_capabilities, ap_client):
    yield
    try:
        firmware = ap_client.get_firmware_version()
    except Exception:
        firmware = None
    write_environment_properties(
        allure_results_dir=testbed_config.settings.allure_results_dir,
        ap_serial=testbed_config.ap.serial,
        ap_firmware=firmware,
        controller_url=testbed_config.controller.base_url,
        testbed_name=testbed_config.testbed.name,
        capabilities=testbed_capabilities,
    )

"""
Offline tests for ``benchd.testbed``, ``benchd.auth`` and ``benchd.importer``.

The testbed and auth modules are the two places the console handles secrets:
a per-run config that carries the AP and station passwords, and the bench
password that gates the console itself. ``redacted()`` is what stands between
those passwords and a browser, so its coverage is deliberately paranoid.
"""
from __future__ import annotations

import copy
import stat

import pytest
import yaml

from benchd import auth, importer, paths, store, testbed
from tests.unit.conftest import write_environment, write_result

BASE = {
    "testbed": {"name": "bench", "operator": "firas"},
    "ap": {"host": "10.0.127.1", "user": "admin", "password": "old-ap-pw",
           "cleanup": "none"},
    "station": {"host": "10.0.125.190", "user": "pi", "password": "sta-pw",
                "root_password": "sta-root-pw", "iface": "wlan0"},
    "external": {
        "radius": {"host": "10.0.125.190", "secret": "radius-shared-secret",
                   "identity": "testuser", "password": "radius-user-pw"},
        "local_radius_users": [{"username": "alice", "password": "alice-pw"}],
        "vlan": {"ids": [100, 200]},
    },
}


@pytest.fixture
def base_testbed(bench_paths):
    paths.BASE_TESTBED.write_text(yaml.safe_dump(BASE))
    return copy.deepcopy(BASE)


# ── testbed.build() ──────────────────────────────────────────────────────────

def test_build_substitutes_only_the_ap_block(base_testbed):
    cfg = testbed.build("10.0.127.220", "root", "new-pw")
    assert cfg["ap"] == {"host": "10.0.127.220", "user": "root", "password": "new-pw",
                         "cleanup": "factory_reset"}
    assert cfg["station"] == BASE["station"]
    assert cfg["external"] == BASE["external"]
    assert cfg["testbed"] == BASE["testbed"]


def test_build_strips_whitespace_and_defaults_an_empty_user_to_root(base_testbed):
    cfg = testbed.build(" 10.0.127.220 ", "  ", "pw", cleanup="restore_agent")
    assert cfg["ap"]["host"] == "10.0.127.220"
    assert cfg["ap"]["user"] == "root"
    assert cfg["ap"]["cleanup"] == "restore_agent"


def test_build_works_with_no_base_file_at_all(bench_paths):
    """A fresh checkout has no config/testbed.yaml; the form still has to open."""
    assert not paths.BASE_TESTBED.exists()
    cfg = testbed.build("10.0.127.220", "root", "pw")
    assert cfg == {"ap": {"host": "10.0.127.220", "user": "root", "password": "pw",
                          "cleanup": "factory_reset"}}


def test_build_does_not_mutate_the_cached_base(base_testbed):
    first = testbed.build("10.0.127.220", "root", "pw")
    first["station"]["password"] = "tampered"
    second = testbed.build("10.0.127.221", "root", "pw")
    assert second["station"]["password"] == "sta-pw"


# ── testbed.validate() ───────────────────────────────────────────────────────

def test_a_valid_config_validates_to_a_model_with_no_error(base_testbed):
    cfg, err = testbed.validate(testbed.build("10.0.127.220", "root", "pw"))
    assert err == ""
    assert cfg.ap.host == "10.0.127.220"
    assert cfg.external.radius.secret == "radius-shared-secret"


def test_a_missing_station_is_a_readable_error_not_an_exception(base_testbed):
    cfg = testbed.build("10.0.127.220", "root", "pw")
    del cfg["station"]
    model, err = testbed.validate(cfg)
    assert model is None
    assert "station" in err and "required" in err.lower()


def test_an_unknown_cleanup_mode_names_the_field_in_the_error(base_testbed):
    model, err = testbed.validate(testbed.build("10.0.127.220", "root", "pw", cleanup="nuke"))
    assert model is None
    assert err.startswith("ap.cleanup:")
    assert "factory_reset" in err


def test_several_problems_are_all_reported(base_testbed):
    cfg = testbed.build("", "root", "pw")
    cfg["station"] = {"host": "10.0.125.190"}         # no password
    cfg["ap"]["port"] = "not-a-port"
    model, err = testbed.validate(cfg)
    assert model is None
    assert "ap.port" in err and "station.password" in err


# ── testbed.write() ──────────────────────────────────────────────────────────

def test_write_creates_parents_and_keeps_the_file_private(base_testbed, tmp_path):
    cfg = testbed.build("10.0.127.220", "root", "pw")
    dest = testbed.write(cfg, tmp_path / "runs" / "r1" / "testbed.yaml")
    assert yaml.safe_load(dest.read_text()) == cfg
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600


# ── testbed.redacted() ───────────────────────────────────────────────────────

def _leaked(cfg: dict, secrets: list[str]) -> list[str]:
    text = yaml.safe_dump(cfg)
    return [s for s in secrets if s in text]


def test_redacted_removes_every_credential_in_the_config(base_testbed):
    """
    This copy goes to a browser and sits next to the results. Any of these
    strings surviving means a password on a web page.
    """
    cfg = testbed.build("10.0.127.220", "root", "ap-root-pw")
    safe = testbed.redacted(cfg)
    assert _leaked(safe, ["ap-root-pw", "sta-pw", "sta-root-pw",
                          "radius-shared-secret", "radius-user-pw", "alice-pw"]) == []
    assert safe["ap"]["password"] == testbed._REDACT
    assert safe["station"]["password"] == testbed._REDACT
    assert safe["station"]["root_password"] == testbed._REDACT
    assert safe["external"]["radius"]["secret"] == testbed._REDACT
    assert safe["external"]["radius"]["password"] == testbed._REDACT
    assert safe["external"]["local_radius_users"][0]["password"] == testbed._REDACT


def test_redacted_keeps_everything_that_is_not_a_secret(base_testbed):
    cfg = testbed.build("10.0.127.220", "root", "ap-root-pw")
    safe = testbed.redacted(cfg)
    assert safe["ap"]["host"] == "10.0.127.220"
    assert safe["station"]["host"] == "10.0.125.190"
    assert safe["external"]["radius"]["identity"] == "testuser"
    assert safe["external"]["local_radius_users"][0]["username"] == "alice"
    assert safe["external"]["vlan"] == {"ids": [100, 200]}


def test_redacted_is_a_copy_and_leaves_the_real_config_intact(base_testbed):
    cfg = testbed.build("10.0.127.220", "root", "ap-root-pw")
    before = copy.deepcopy(cfg)
    testbed.redacted(cfg)
    assert cfg == before


def test_redacted_copes_with_a_minimal_config():
    """No external block, no station root password — nothing to trip over."""
    cfg = {"ap": {"host": "h", "password": "p"}, "station": {"host": "s", "password": "q"}}
    safe = testbed.redacted(cfg)
    assert safe["ap"]["password"] == testbed._REDACT
    assert safe["station"]["password"] == testbed._REDACT
    assert "root_password" not in safe["station"]


def test_redacted_copes_with_explicit_nulls():
    """
    ``external: {radius: null}`` is valid YAML and a valid TestbedConfig —
    it is how a profile says "no RADIUS here". A null must read as absent,
    not raise on the way to the browser.
    """
    cfg = {"ap": {"host": "h", "password": "p"},
           "station": {"host": "s", "password": "q", "root_password": None},
           "external": {"radius": None, "vlan": None}}
    assert testbed.validate(cfg)[1] == ""
    safe = testbed.redacted(cfg)
    assert safe["external"] == {"radius": None, "vlan": None}
    assert safe["station"]["root_password"] is None


# ── auth ─────────────────────────────────────────────────────────────────────

def test_a_hashed_password_verifies_and_a_wrong_one_does_not():
    stored = auth.hash_password("correct horse")
    assert auth.verify("correct horse", stored)
    assert not auth.verify("correct horsf", stored)
    assert not auth.verify("", stored)


def test_the_hash_is_salted_so_the_same_password_hashes_differently():
    assert auth.hash_password("pw") != auth.hash_password("pw")
    assert auth.hash_password("pw", salt="fixed") == auth.hash_password("pw", salt="fixed")


def test_the_stored_form_records_the_algorithm_and_iteration_count():
    algo, iters, salt, digest = auth.hash_password("pw", salt="abc").split("$")
    assert algo == "pbkdf2_sha256"
    assert int(iters) == auth._ITERATIONS >= 100_000
    assert salt == "abc" and len(digest) == 64


@pytest.mark.parametrize("stored", [
    "", "garbage", "pbkdf2_sha256$notanumber$salt$00", "a$b$c", None, 42,
])
def test_a_malformed_stored_hash_fails_closed(stored):
    """A damaged benchd.env must lock the console, not crash the login route."""
    assert auth.verify("pw", stored) is False


def test_check_is_false_until_a_password_is_set(bench_paths):
    assert not auth.configured()
    assert not auth.check("anything")


def test_set_password_writes_a_private_env_file_and_check_honours_it(bench_paths):
    auth.set_password("bench-pw")
    assert paths.ENV_FILE.exists()
    assert str(paths.ENV_FILE).startswith(str(bench_paths))
    assert stat.S_IMODE(paths.ENV_FILE.stat().st_mode) == 0o600
    assert "bench-pw" not in paths.ENV_FILE.read_text()      # hashed at rest
    assert auth.configured()
    assert auth.check("bench-pw")
    assert not auth.check("bench-pw!")


def test_set_password_keeps_the_existing_session_key(bench_paths):
    """Rotating the password must not log everyone out by rotating the key too."""
    key = auth.secret_key()
    auth.set_password("one")
    auth.set_password("two")
    assert auth.secret_key() == key
    assert auth.check("two") and not auth.check("one")


def test_secret_key_is_generated_once_and_persisted(bench_paths):
    first = auth.secret_key()
    assert len(first) == 64
    assert auth.secret_key() == first
    assert f"BENCH_SECRET_KEY={first}" in paths.ENV_FILE.read_text()


def test_env_parsing_ignores_comments_and_blank_lines(bench_paths):
    paths.ENV_FILE.write_text("# header\n\nBENCH_PASSWORD_HASH = x\nNOEQUALS\n")
    assert auth._read_env() == {"BENCH_PASSWORD_HASH": "x"}


# ── importer ─────────────────────────────────────────────────────────────────

def test_importing_results_records_provenance_from_the_environment_file(tmp_path):
    src = tmp_path / "old-sweep"
    write_result("staging", "psk", "5G", "passed")
    write_result("staging", "wpa", "2G", "failed", message="x")
    write_environment("staging", **{"AP.Model": "EAP102", "AP.Firmware": "2.9.0",
                                    "Station.Host": "10.0.125.190"})
    store.results_dir("staging").rename(src)
    store.delete_run("staging")

    run_id, err = importer.import_results(src, label="Sweep 3", note="pre-console",
                                         generate=False)
    assert err == ""
    assert run_id.endswith("-eap102")
    meta = store.read_meta(run_id)
    assert meta.imported is True
    assert meta.status == "failed"              # one failure in the results
    assert meta.label == "Sweep 3" and meta.note == "pre-console"
    assert meta.ap["model"] == "EAP102" and meta.ap["firmware"] == "2.9.0"
    assert meta.station == {"Host": "10.0.125.190"}
    assert meta.totals["total"] == 2
    assert set(store.cases(run_id)) == {("psk", "5G"), ("wpa", "2G")}
    assert src.exists()                         # a copy, the original is untouched
    assert not store.run_dir(f"import-{src.name}").exists()


def test_importing_a_clean_sweep_is_recorded_as_passed(tmp_path):
    src = tmp_path / "clean"
    write_result("staging", "psk", "5G", "passed")
    store.results_dir("staging").rename(src)
    run_id, _ = importer.import_results(src, generate=False)
    assert store.read_meta(run_id).status == "passed"


def test_importing_something_that_is_not_results_is_refused(tmp_path):
    assert importer.import_results(tmp_path / "missing", generate=False) == (
        None, f"{tmp_path / 'missing'} is not a directory")
    empty = tmp_path / "empty"
    empty.mkdir()
    run_id, err = importer.import_results(empty, generate=False)
    assert run_id is None and "no Allure results" in err
    assert not any(paths.RUNS.iterdir()) if paths.RUNS.exists() else True

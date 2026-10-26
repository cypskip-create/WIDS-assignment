from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest


@pytest.mark.parametrize("page", ["Security Overview", "Wireless Traffic Monitor", "Attack Detection", "Machine Learning Analytics", "Security Incidents", "Settings"])
def test_dashboard_pages_empty_database(tmp_path, monkeypatch, page):
    monkeypatch.setenv("SENTINEL_DB", str(tmp_path/"dashboard.sqlite3"))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1]/"app.py"), default_timeout=30).run()
    app.sidebar.radio[0].set_value(page).run()
    assert not app.exception


def test_dashboard_displays_persisted_incident(tmp_path, monkeypatch):
    from wids.storage import Storage
    from wids.fixture import generate_fixture
    from wids.replay import replay_sync
    from wids.config import Settings
    db = tmp_path/"dashboard.sqlite3"
    replay_sync(generate_fixture(tmp_path/"fixture.pcap"), Storage(db), Settings(), "synthetic", model=False)
    monkeypatch.setenv("SENTINEL_DB", str(db))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1]/"app.py"), default_timeout=30).run()
    assert not app.exception
    assert any("Deauthentication flood" in element.value for element in app.warning)
    app.sidebar.radio[0].set_value("Security Incidents").run()
    assert not app.exception and app.dataframe[0].value.shape[0] == 1

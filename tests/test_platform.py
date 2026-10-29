from sentinelforge import platform


def test_isolation_and_case_workflow(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELFORGE_DB_PATH", str(tmp_path / "test.db"))
    identifier = platform.save_report("alpha", {"findings": []}, "abc")
    assert len(platform.reports("alpha")) == 1
    assert platform.reports("beta") == []
    assert platform.create_case("beta", identifier) is None
    case_id = platform.create_case("alpha", identifier)
    assert case_id
    assert platform.cases("alpha")[0]["report_id"] == identifier
    assert platform.cases("beta") == []

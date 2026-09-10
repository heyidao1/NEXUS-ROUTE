from bounty import safe_hunter


def test_scope_matching_is_explicit():
    assert safe_hunter.host_in_scope("api.example.com", ["*.example.com"])
    assert safe_hunter.host_in_scope("example.com", ["*.example.com"])
    assert not safe_hunter.host_in_scope("example.net", ["*.example.com"])


def test_passive_mode_never_calls_active_probe(monkeypatch):
    monkeypatch.setattr(safe_hunter, "crtsh_names", lambda domain: ["a.example.com"])
    monkeypatch.setattr(safe_hunter, "subfinder_names", lambda domain: [])
    monkeypatch.setattr(safe_hunter.time, "sleep", lambda *_: None)
    monkeypatch.setattr(
        safe_hunter,
        "dns_snapshot",
        lambda host: {"host": host, "a": [], "aaaa": [], "cname": [], "dangling_cname": False},
    )
    monkeypatch.setattr(safe_hunter, "probe_host", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("active probe called")))
    result = safe_hunter.run_program({
        "id": "passive-test",
        "program_name": "passive",
        "platform": "test",
        "automation_mode": "passive_only",
        "passive_seed_domains": ["example.com"],
        "scope": {"include": ["*.example.com"]},
    })
    assert result["direct_requests_used"] == 0
    assert result["passive_discovered_count"] == 1


def test_active_mode_only_probes_curated_seed_hosts(monkeypatch):
    seen = []
    monkeypatch.setattr(safe_hunter, "crtsh_names", lambda domain: ["discovered.example.com"])
    monkeypatch.setattr(safe_hunter, "subfinder_names", lambda domain: [])
    monkeypatch.setattr(safe_hunter.time, "sleep", lambda *_: None)
    monkeypatch.setattr(safe_hunter, "dns_snapshot", lambda host: {"host": host, "a": [], "aaaa": [], "cname": [], "dangling_cname": False})
    monkeypatch.setattr(safe_hunter, "probe_host", lambda host, program, budget: (seen.append(host) or ({"host": host}, [])))
    safe_hunter.run_program({
        "id": "active-test",
        "program_name": "active",
        "platform": "test",
        "automation_mode": "low_impact_read_only",
        "max_requests_per_run": 10,
        "passive_seed_domains": ["example.com"],
        "active_seed_hosts": ["www.example.com"],
        "scope": {"include": ["*.example.com"]},
    })
    assert seen == ["www.example.com"]

def test_discovered_root_probe_is_opt_in_and_limited(monkeypatch):
    seen = []
    monkeypatch.setattr(safe_hunter, "crtsh_names", lambda domain: [f"h{i}.example.com" for i in range(12)])
    monkeypatch.setattr(safe_hunter, "subfinder_names", lambda domain: [])
    monkeypatch.setattr(safe_hunter.time, "sleep", lambda *_: None)
    monkeypatch.setattr(safe_hunter, "dns_snapshot", lambda host: {"host": host, "a": [], "aaaa": [], "cname": [], "dangling_cname": False})
    monkeypatch.setattr(safe_hunter, "probe_host", lambda host, program, budget: ({"host": host}, []))
    monkeypatch.setattr(safe_hunter, "probe_discovered_root", lambda host, program, budget: (seen.append(host) or ({"host": host}, [])))
    safe_hunter.run_program({
        "id": "bounded-test", "program_name": "bounded", "platform": "test",
        "automation_mode": "low_impact_read_only", "max_requests_per_run": 20,
        "passive_seed_domains": ["example.com"], "active_seed_hosts": ["www.example.com"],
        "probe_discovered_roots": True, "max_discovered_active_hosts": 3,
        "scope": {"include": ["*.example.com"]},
    })
    assert len(seen) == 3
    assert "www.example.com" not in seen

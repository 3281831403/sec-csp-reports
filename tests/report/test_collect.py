"""collect 引擎的验收测试，共 15 条，全部为红。

前 10 条逐一对应题面中的 10 个缺陷，后 5 条覆盖去重、限流、
伪造报告隔离与批次独立性。测试不得修改。
"""

import json

from engine.report import collect


POLICY = {
    "dedup": True,
    "rate_limit": {"limit": 10, "window_ms": 60000},
    "trusted_sources": ["https://app.example"],
}


def make_report(
    directive="script-src",
    blocked_url="https://cdn.example/app.js",
    source="https://app.example/page",
    timestamp_ms=0,
):
    return {
        "directive": directive,
        "blocked_url": blocked_url,
        "source": source,
        "timestamp_ms": timestamp_ms,
    }


def test_parse_only_duplicates_are_not_stored():
    """缺陷 1：只有解析不做去重，同一条告警重复入库。"""
    body = json.dumps(
        {
            "directive": "script-src",
            "blocked_url": "https://cdn.example/app.js",
            "source": "https://app.example/page",
            "timestamp_ms": 1000,
        }
    )
    first = collect.parse_report(body)
    second = collect.parse_report(body)
    assert first == second

    result = collect.report_batch(
        [{"bucket_ms": 1000, "reports": [first, second]}], POLICY
    )
    assert result["total"] == 1
    assert result["batches"][0]["kept"] == 1
    assert result["batches"][0]["counts"] == {1000: 1}


def test_dedup_key_ignores_timestamp():
    """缺陷 2：去重键包含时间戳，同一问题每次都是新键。"""
    early = make_report(timestamp_ms=1000)
    late = make_report(timestamp_ms=999999999)
    assert collect.dedup_key(early) == collect.dedup_key(late)


def test_dedup_key_includes_directive():
    """缺陷 3：去重键不含指令，不同指令被合并。"""
    script = make_report(directive="script-src")
    image = make_report(directive="img-src")
    assert collect.dedup_key(script) != collect.dedup_key(image)


def test_normalize_url_strips_fragment_and_userinfo():
    """缺陷 4：地址规范化不去片段，带锚点的地址被当成不同来源。"""
    assert (
        collect.normalize_url("HTTPS://CDN.Example:443/a.js?x=1#frag")
        == "https://cdn.example/a.js?x=1"
    )
    assert (
        collect.normalize_url("https://app.example@evil.example/x#y")
        == "https://evil.example/x"
    )
    assert (
        collect.normalize_url("https://app.example/page#top")
        == "https://app.example/page"
    )


def test_aggregate_uses_time_buckets_not_arrival_order():
    """缺陷 5：聚合按到达顺序而不是时间桶，乱序报告算错。"""
    reports = [
        make_report(timestamp_ms=1700),
        make_report(timestamp_ms=100),
        make_report(timestamp_ms=1500),
        make_report(timestamp_ms=900),
    ]
    expected = {0: 2, 1000: 2}
    assert collect.aggregate(reports, 1000) == expected
    assert collect.aggregate(list(reversed(reports)), 1000) == expected


def test_rate_limit_counts_by_source_not_dedup_key():
    """缺陷 6：限流按去重键计数，换键即可绕过。"""
    policy = {"limit": 2, "window_ms": 60000, "counters": {}}
    source = "https://app.example/page"
    assert collect.rate_limit(source, policy, 1000) is True
    assert collect.rate_limit(source, policy, 1001) is True
    assert collect.rate_limit(source, policy, 1002) is False
    # 伪造带锚点的同一来源也不能换一个键继续上报。
    assert collect.rate_limit(source + "#forged", policy, 1003) is False


def test_rate_limit_prunes_expired_counters():
    """缺陷 7：限流不清理过期计数，长期运行后全部被限。"""
    policy = {"limit": 1, "window_ms": 1000, "counters": {}}
    source = "https://app.example/page"
    assert collect.rate_limit(source, policy, 0) is True
    assert collect.rate_limit(source, policy, 500) is False
    assert collect.rate_limit(source, policy, 1000) is True


def test_sanitize_escapes_quotes_and_ampersand_in_forged_report():
    """缺陷 8：清洗只转义尖括号，引号与与号未处理。"""
    forged = {
        "directive": 'script-src" onload="alert(1)',
        "blocked_url": "https://evil.example/?a=1&b=2",
        "source": "<script>alert('x')</script>",
        "timestamp_ms": 1234,
    }
    cleaned = collect.sanitize(forged)

    assert cleaned["directive"] == "script-src&quot; onload=&quot;alert(1)"
    assert cleaned["blocked_url"] == "https://evil.example/?a=1&amp;b=2"
    assert cleaned["source"] == "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
    assert cleaned["timestamp_ms"] == 1234
    assert forged["directive"] == 'script-src" onload="alert(1)'


def test_validate_policy_requires_source_validation():
    """缺陷 9：策略校验不检查是否校验来源页。"""
    incomplete = {"dedup": True, "rate_limit": {"limit": 5, "window_ms": 1000}}
    assert collect.validate_policy(incomplete) == ["missing_source_validation"]

    valid = {
        "dedup": True,
        "rate_limit": {"limit": 5, "window_ms": 1000},
        "trusted_sources": ["https://app.example"],
    }
    assert collect.validate_policy(valid) == []

    # 伪造来源配置带 userinfo，规范化后与自身不等，必须拒绝。
    forged = {
        "dedup": True,
        "rate_limit": {"limit": 5, "window_ms": 1000},
        "trusted_sources": ["https://app.example@evil.example"],
    }
    assert collect.validate_policy(forged) == ["missing_source_validation"]


def test_report_batch_isolates_buckets_between_batches():
    """缺陷 10：批量处理复用聚合桶，后一批次命中前一批次的计数。"""
    result = collect.report_batch(
        [
            {"bucket_ms": 1000, "reports": [make_report(timestamp_ms=100)]},
            {"bucket_ms": 1000, "reports": [make_report(timestamp_ms=500)]},
        ],
        POLICY,
    )
    assert result["batches"][0]["counts"] == {0: 1}
    assert result["batches"][1]["counts"] == {0: 1}
    assert result["total"] == 2


def test_identical_reports_counted_once():
    """相同报告只计一次。"""
    report = make_report(timestamp_ms=1234)
    result = collect.report_batch(
        [{"bucket_ms": 1000, "reports": [report, dict(report), dict(report)]}],
        POLICY,
    )
    assert result["batches"][0]["kept"] == 1
    assert result["batches"][0]["dropped"] == 2
    assert result["batches"][0]["counts"] == {1000: 1}


def test_different_directives_counted_separately():
    """不同指令分开计。"""
    result = collect.report_batch(
        [
            {
                "bucket_ms": 1000,
                "reports": [
                    make_report(directive="script-src", timestamp_ms=0),
                    make_report(directive="img-src", timestamp_ms=0),
                ],
            }
        ],
        POLICY,
    )
    assert result["batches"][0]["kept"] == 2
    assert result["batches"][0]["counts"] == {0: 2}


def test_source_over_limit_is_rate_limited():
    """超限来源被限流。"""
    policy = {"limit": 2, "window_ms": 1000, "counters": {}}
    source = "https://app.example/page"
    allowed = [
        collect.rate_limit(source, policy, 100),
        collect.rate_limit(source, policy, 200),
        collect.rate_limit(source, policy, 300),
    ]
    assert allowed == [True, True, False]
    assert collect.rate_limit("https://other.example/x", policy, 400) is True


def test_fragment_does_not_change_dedup_key():
    """片段不影响去重。"""
    plain = make_report(source="https://app.example/page")
    anchored = make_report(source="https://app.example/page#section")
    assert collect.dedup_key(plain) == collect.dedup_key(anchored)


def test_two_batches_match_individual_processing():
    """两批独立处理与单独处理相同。"""
    first = [
        make_report(directive="script-src", timestamp_ms=0),
        make_report(directive="img-src", timestamp_ms=1500),
    ]
    second = [make_report(directive="style-src", timestamp_ms=1200)]

    result = collect.report_batch(
        [
            {"bucket_ms": 1000, "reports": first},
            {"bucket_ms": 1000, "reports": second},
        ],
        POLICY,
    )
    assert result["batches"][0]["counts"] == collect.aggregate(first, 1000)
    assert result["batches"][1]["counts"] == collect.aggregate(second, 1000)
    assert result["total"] == 3
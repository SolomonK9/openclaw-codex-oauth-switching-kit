#!/usr/bin/env python3
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "oauth_pool_router.py"
spec = importlib.util.spec_from_file_location("oauth_pool_router", MODULE_PATH)
router = importlib.util.module_from_spec(spec)
spec.loader.exec_module(router)


class RateLimitRoutingTests(unittest.TestCase):
    def setUp(self):
        self.config = router.default_config()
        self.config["accounts"] = [
            {"profileId": "codex-oauth-a", "enabled": True, "name": "A", "priority": 1, "projects": ["project-a"]},
            {"profileId": "codex-oauth-b", "enabled": True, "name": "B", "priority": 1, "projects": ["project-a"]},
        ]
        self.state = router.default_state()
        router.ensure_account_state(self.config, self.state)
        for pid in ["codex-oauth-a", "codex-oauth-b"]:
            acc = self.state["accounts"][pid]
            acc["usage"] = {"available": True, "fiveHourRemaining": 80.0, "weekRemaining": 80.0, "observedAt": router.ts(), "source": "provider-api-per-profile"}
            acc["health"] = {"healthy": True, "expired": False, "observedAt": router.ts(), "stage": "healthy", "reason": None}

    def test_normalizes_common_rate_limit_variants(self):
        variants = [
            ("", "HTTP 429 too many requests"),
            ("ratelimit", ""),
            ("TooManyRequests", ""),
            ("server_error", "provider overloaded, try again later"),
            ("", "quota exceeded"),
            ("", "ChatGPT usage limit"),
        ]
        for reason, raw in variants:
            self.assertEqual(router.normalize_runtime_failover_reason(reason, raw), "rate_limit")

    def test_live_rate_limit_preserves_capacity_and_blocks_temporarily(self):
        acc = self.state["accounts"]["codex-oauth-a"]
        router.apply_live_fail_penalty(self.config, acc, kind="rate_limit", minutes=20, raw="429")
        self.assertEqual(acc["usage"]["fiveHourRemaining"], 80.0)
        self.assertEqual(acc["usage"]["weekRemaining"], 80.0)
        self.assertTrue(router.is_live_failover_active(acc))
        self.assertNotIn("codex-oauth-a", router.healthy_profiles(self.config, self.state))

    def test_duplicate_shorter_cooldown_does_not_shorten_existing_cooldown(self):
        acc = self.state["accounts"]["codex-oauth-a"]
        first = router.apply_live_fail_penalty(self.config, acc, kind="rate_limit", minutes=120, raw="usage limit")
        second = router.apply_live_fail_penalty(self.config, acc, kind="rate_limit", minutes=5, raw="retry soon")
        first_until = router.parse_iso(first["until"])
        second_until = router.parse_iso(second["until"])
        self.assertGreaterEqual(second_until, first_until - router.dt.timedelta(seconds=2))

    def test_recent_rate_limit_demotes_hot_profile_even_with_more_capacity(self):
        self.state["accounts"]["codex-oauth-a"]["usage"]["weekRemaining"] = 95.0
        self.state["accounts"]["codex-oauth-a"]["usage"]["fiveHourRemaining"] = 95.0
        self.state["accounts"]["codex-oauth-b"]["usage"]["weekRemaining"] = 40.0
        self.state["accounts"]["codex-oauth-b"]["usage"]["fiveHourRemaining"] = 40.0
        self.state["accounts"]["codex-oauth-a"]["failureEvents"] = [{"at": router.ts(), "reason": "runtime_rate_limit:429"}]
        order = router.preferred_healthy_order(self.config, self.state, current_order_hint=["codex-oauth-a", "codex-oauth-b"])
        self.assertEqual(order["ordered"][0], "codex-oauth-b")
        detail_a = next(x for x in order["details"] if x["profileId"] == "codex-oauth-a")
        self.assertGreater(detail_a["throttlePenalty"], 0)


if __name__ == "__main__":
    unittest.main()

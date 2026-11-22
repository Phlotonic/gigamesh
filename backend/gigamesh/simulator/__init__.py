"""Multi-attacker benchmark and live simulation corpus."""

from .corpus import AttackScenario, build_attack_scenarios, build_benign_baseline_events

__all__ = ["AttackScenario", "build_attack_scenarios", "build_benign_baseline_events"]

"""Shared result type: findings with a level, a stable code and a concrete fix."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# INFO never affects the verdict. PASS < WARN < FAIL.
_RANK = {"INFO": 0, "PASS": 1, "WARN": 2, "FAIL": 3}


@dataclass
class Finding:
    level: str  # PASS | INFO | WARN | FAIL
    code: str
    message: str
    fix: str | None = None


@dataclass
class Report:
    title: str
    findings: list[Finding] = field(default_factory=list)
    sections: list[tuple[str, list[str]]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def add(self, level: str, code: str, message: str, fix: str | None = None) -> None:
        assert level in _RANK, level
        self.findings.append(Finding(level, code, message, fix))

    def section(self, heading: str, lines: list[str]) -> None:
        self.sections.append((heading, lines))

    @property
    def verdict(self) -> str:
        worst = "PASS"
        for f in self.findings:
            if _RANK[f.level] > _RANK[worst]:
                worst = f.level
        return worst

    def codes(self, level: str | None = None) -> set[str]:
        return {f.code for f in self.findings if level is None or f.level == level}

    def render(self) -> str:
        out = [f"{self.title}", f"VERDICT: {self.verdict}", ""]
        order = ["FAIL", "WARN", "INFO", "PASS"]
        for lvl in order:
            for f in self.findings:
                if f.level == lvl:
                    out.append(f"[{f.level}] {f.message}")
                    if f.fix:
                        out.append(f"       fix: {f.fix}")
        for heading, lines in self.sections:
            out.append("")
            out.append(f"{heading}:")
            out.extend(f"  {line}" for line in lines)
        return "\n".join(out)

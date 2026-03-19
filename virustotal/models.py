from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class AnalysisStats:
    """Maps to attributes.last_analysis_stats"""
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0
    confirmed_timeout: int = 0
    failure: int = 0
    type_unsupported: int = 0

    @property
    def total_scanned(self) -> int:
        """Engines that produced a verdict — matches VT's own score denominator."""
        return self.malicious + self.suspicious + self.undetected + self.harmless

    @property
    def total_engines(self) -> int:
        """All engines, including timeouts and failures."""
        return (
            self.malicious + self.suspicious + self.undetected
            + self.harmless + self.timeout + self.confirmed_timeout
            + self.failure + self.type_unsupported
        )

    @property
    def verdict(self) -> str:
        if self.malicious >= 5:
            return "malicious"
        if self.malicious > 0 or self.suspicious > 0:
            return "suspicious"
        return "undetected"

    @classmethod
    def from_api(cls, d: dict) -> AnalysisStats:
        return cls(
            malicious=d.get("malicious", 0),
            suspicious=d.get("suspicious", 0),
            undetected=d.get("undetected", 0),
            harmless=d.get("harmless", 0),
            timeout=d.get("timeout", 0),
            confirmed_timeout=d.get("confirmed-timeout", 0),
            failure=d.get("failure", 0),
            type_unsupported=d.get("type-unsupported", 0),
        )


@dataclass
class EngineResult:
    """Maps to one entry in attributes.last_analysis_results"""
    engine_name: str
    category: str
    result: str | None
    engine_version: str | None = None
    engine_update: str | None = None
    method: str | None = None

    @classmethod
    def from_api(cls, name: str, d: dict) -> EngineResult:
        return cls(
            engine_name=d.get("engine_name", name),
            category=d.get("category", "undetected"),
            result=d.get("result"),
            engine_version=d.get("engine_version"),
            engine_update=d.get("engine_update"),
            method=d.get("method"),
        )


@dataclass
class VTFileSummary:
    """Subset of attributes from /files/{id} relevant to the Summary tab."""
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    meaningful_name: str = ""
    type_description: str = ""
    reputation: int = 0
    tags: list[str] = field(default_factory=list)
    first_submission_date: int = 0
    last_analysis_date: int = 0
    stats: AnalysisStats = field(default_factory=AnalysisStats)
    engine_results: list[EngineResult] = field(default_factory=list)
    suggested_threat_label: str = ""
    ai_analysis: str = ""
    ai_verdict: str = ""

    @classmethod
    def from_api(cls, attrs: dict) -> VTFileSummary:
        results = [
            EngineResult.from_api(name, data)
            for name, data in attrs.get("last_analysis_results", {}).items()
        ]

        ptc = attrs.get("popular_threat_classification", {})
        suggested_label = ptc.get("suggested_threat_label", "")

        ai_analysis = ""
        ai_verdict = ""
        for entry in attrs.get("crowdsourced_ai_results", []):
            if entry.get("category") == "code_insight":
                ai_analysis = entry.get("analysis", "")
                ai_verdict = entry.get("verdict", "")
                break

        return cls(
            sha256=attrs.get("sha256", ""),
            md5=attrs.get("md5", ""),
            sha1=attrs.get("sha1", ""),
            meaningful_name=attrs.get("meaningful_name", ""),
            type_description=attrs.get("type_description", ""),
            reputation=attrs.get("reputation", 0),
            tags=attrs.get("tags", []),
            first_submission_date=attrs.get("first_submission_date", 0),
            last_analysis_date=attrs.get("last_analysis_date", 0),
            stats=AnalysisStats.from_api(attrs.get("last_analysis_stats", {})),
            engine_results=results,
            suggested_threat_label=suggested_label,
            ai_analysis=ai_analysis,
            ai_verdict=ai_verdict,
        )


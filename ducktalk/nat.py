"""NAT / reachability assessment built only from STUN observations.

DuckTalk does not perform port prediction and never falls back to a relay.
The assessment below is therefore a best-effort classification, not a
guarantee that a direct path exists.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field

from .stun import StunObservation

CODES = {
    "open": "No NAT observed (public address equals local address)",
    "nat": "NAT present",
    "port_mapping": "Address-preserving NAT / port mapping",
    "symmetric_suspected": "Symmetric NAT or per-destination mapping suspected",
    "multi_public": "Multiple public addresses observed (multi-WAN or upstream NAT pool)",
    "cgnat_suspected": "Carrier-grade NAT (100.64.0.0/10) suspected",
    "double_nat_suspected": "Upstream NAT is also private (double NAT suspected)",
    "udp_blocked": "No STUN response: UDP blocked, firewalled, or offline",
    "not_tested": "Not tested",
}


@dataclass
class SocketAssessment:
    family: int
    local_ip: str | None
    local_port: int | None
    observations: list[StunObservation]
    code: str
    detail: list[str] = field(default_factory=list)

    @property
    def successful(self) -> list[StunObservation]:
        return [o for o in self.observations if o.ok]

    @property
    def mappings(self) -> list[tuple[str, int]]:
        seen: list[tuple[str, int]] = []
        for observation in self.successful:
            if observation.mapped and observation.mapped not in seen:
                seen.append(observation.mapped)
        return seen


def _is_private_or_cgnat(address: str) -> tuple[bool, bool]:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False, False
    return ip.is_private, ip.is_global is False and ip in ipaddress.ip_network("100.64.0.0/10")


def assess_socket(
    family: int,
    local_ip: str | None,
    local_port: int | None,
    observations: list[StunObservation],
) -> SocketAssessment:
    if not observations:
        return SocketAssessment(family, local_ip, local_port, [], "not_tested",
                                ["No STUN servers configured."])
    successful = [o for o in observations if o.ok]
    if not successful:
        errors = sorted({o.error or "unknown error" for o in observations})
        return SocketAssessment(family, local_ip, local_port, observations, "udp_blocked",
                                ["STUN did not answer: " + "; ".join(errors)])
    mappings = []
    for observation in successful:
        if observation.mapped and observation.mapped not in mappings:
            mappings.append(observation.mapped)

    detail: list[str] = []
    if len(mappings) > 1:
        ips = {ip for ip, _ in mappings}
        if len(ips) > 1:
            return SocketAssessment(family, local_ip, local_port, observations, "multi_public",
                                    ["Mappings: " + ", ".join(f"{ip}:{port}" for ip, port in mappings)])
        return SocketAssessment(
            family, local_ip, local_port, observations, "symmetric_suspected",
            ["Different mapped ports across STUN servers: "
             + ", ".join(f"{ip}:{port}" for ip, port in mappings)
             + ". Direct UDP between peers may fail; no port prediction is attempted."],
        )

    mapped_ip, mapped_port = mappings[0]
    try:
        local_is_public = bool(local_ip and ipaddress.ip_address(local_ip).is_global)
        mapped_is_private, mapped_is_cgnat = _is_private_or_cgnat(mapped_ip)
        local_private = bool(local_ip and ipaddress.ip_address(local_ip).is_private)
    except ValueError:
        local_is_public = mapped_is_private = mapped_is_cgnat = local_private = False

    if mapped_is_cgnat:
        return SocketAssessment(family, local_ip, local_port, observations, "cgnat_suspected",
                                [f"Public mapping {mapped_ip}:{mapped_port} is in 100.64.0.0/10."])
    if mapped_is_private and local_private:
        return SocketAssessment(family, local_ip, local_port, observations, "double_nat_suspected",
                                [f"Mapping {mapped_ip}:{mapped_port} is private despite a private local address."])
    if local_ip == mapped_ip and local_port == mapped_port:
        return SocketAssessment(family, local_ip, local_port, observations, "open",
                                [f"STUN sees {mapped_ip}:{mapped_port}, identical to the local socket."])
    if local_ip == mapped_ip and local_port != mapped_port:
        return SocketAssessment(family, local_ip, local_port, observations, "port_mapping",
                                [f"Public IP is unchanged but the port maps {local_port} -> {mapped_port}."])
    if local_is_public and mapped_ip != local_ip:
        return SocketAssessment(family, local_ip, local_port, observations, "multi_public",
                                [f"Local {local_ip} but STUN sees {mapped_ip}."])
    detail.append(f"STUN mapping: {mapped_ip}:{mapped_port} for local {local_ip}:{local_port}.")
    return SocketAssessment(family, local_ip, local_port, observations, "nat", detail)


@dataclass
class NatProfile:
    assessments: list[SocketAssessment]
    stun_servers: list[str]
    limitations: list[str] = field(default_factory=list)

    @classmethod
    def from_sockets(
        cls,
        socket_observations: Iterable[tuple[int, str | None, int | None, list[StunObservation]]],
        stun_servers: Iterable[str],
    ) -> NatProfile:
        assessments = [assess_socket(*item) for item in socket_observations]
        limitations = [
            "STUN only tests UDP. TCP inbound reachability is unknown until a peer actually connects.",
            "Symmetric-NAT detection needs at least two independent STUN servers; a single mapping is not proof of cone NAT.",
            "No port prediction, TURN, relay, or firewall bypass is attempted.",
            "A successful mapping does not prove that a peer can reach it; hole punching still has to succeed.",
        ]
        return cls(assessments, list(stun_servers), limitations)

    @property
    def codes(self) -> list[str]:
        return [a.code for a in self.assessments]

    def primary_code(self) -> str:
        priority = [
            "symmetric_suspected",
            "cgnat_suspected",
            "double_nat_suspected",
            "udp_blocked",
            "nat",
            "port_mapping",
            "multi_public",
            "open",
        ]
        for code in priority:
            if code in self.codes:
                return code
        return "not_tested"

    def summary(self) -> str:
        code = self.primary_code()
        human = CODES.get(code, code)
        mappings: list[str] = []
        for assessment in self.assessments:
            for mapped in assessment.mappings:
                text = f"{mapped[0]}:{mapped[1]}"
                if text not in mappings:
                    mappings.append(text)
        if mappings:
            return f"{human} (public mapping: {', '.join(mappings)})"
        return human

    def as_lines(self) -> list[str]:
        lines = ["Network / NAT diagnostics"]
        if not self.stun_servers:
            lines.append("  STUN discovery disabled (host candidates only).")
        for assessment in self.assessments:
            label = "IPv4" if assessment.family == 4 else "IPv6"
            lines.append(f"  {label} UDP socket {assessment.local_ip}:{assessment.local_port}")
            if not assessment.observations:
                lines.append("    no STUN observations")
            for observation in assessment.observations:
                if observation.ok:
                    lines.append(
                        f"    {observation.server}: mapping {observation.mapped_ip}:{observation.mapped_port}"
                        f"  RTT {observation.rtt_ms:.0f} ms" if observation.rtt_ms is not None else
                        f"    {observation.server}: mapping {observation.mapped_ip}:{observation.mapped_port}"
                    )
                else:
                    lines.append(f"    {observation.server}: {observation.error}")
            lines.append(f"    assessment: {CODES.get(assessment.code, assessment.code)}")
            for detail in assessment.detail:
                lines.append(f"    {detail}")
        lines.append("  Limitations:")
        for limitation in self.limitations:
            lines.append(f"    - {limitation}")
        return lines


def format_pair_report(rows: list[dict]) -> list[str]:
    if not rows:
        return ["  (no candidate pairs were attempted)"]
    lines: list[str] = []
    for row in rows:
        pair = row.get("pair", "?")
        proto = row.get("protocol", "?")
        status = row.get("status", "?")
        detail = row.get("detail", "")
        lines.append(f"  {proto.upper():3} {status:16} {pair}  {detail}".rstrip())
    return lines

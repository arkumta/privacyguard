
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

APP_VERSION = "0.2.0"
MAX_SOURCE_BYTES = int(os.getenv("MAX_SOURCE_BYTES", "200000"))

app = FastAPI(
    title="PrivacyGuard Scanner API",
    description=(
        "Local prototype API for Solidity security and privacy checks, "
        "including Horizen and Vela integration review."
    ),
    version=APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class ScanRequest(BaseModel):
    source: str = Field(min_length=1, max_length=200_000)
    filename: str = Field(default="Contract.sol", max_length=100)


def severity_rank(severity: str) -> int:
    return {"High": 0, "Medium": 1, "Low": 2}.get(severity, 3)


def line_number(source: str, index: int) -> int:
    return source.count("\n", 0, max(index, 0)) + 1


def strip_comments(source: str) -> str:
    """Remove Solidity comments without changing offsets or line numbers."""
    pattern = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")

    def replace(match: re.Match[str]) -> str:
        return "".join(
            "\n" if char == "\n" else " "
            for char in match.group(0)
        )

    return pattern.sub(replace, source)


def privacy_checks(source: str) -> list[dict[str, Any]]:
    """Source-level review rules. Findings are leads, not proof of vulnerabilities."""
    results: list[dict[str, Any]] = []
    code = strip_comments(source)

    def add(
        rule_id: str,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
        index: int,
        snippet: str,
    ) -> None:
        results.append({
            "id": f"{rule_id}-{line_number(source, index)}-{len(results)}",
            "rule_id": rule_id,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "line": line_number(source, index),
            "snippet": snippet.strip()[:400],
            "source": "PrivacyGuard heuristic",
        })

    # PG-PRIV-001: Events are generally publicly observable.
    for match in re.finditer(
        r"\bevent\s+\w+\s*\(([^)]*)\)", code, re.DOTALL
    ):
        params = match.group(1)
        sensitive_names = re.findall(
            r"\b(email|phone|name|ip|secret|privateKey|password|ssn|"
            r"personalData|dateOfBirth|homeAddress|medicalRecord)\b",
            params,
            re.IGNORECASE,
        )
        dynamic_type = bool(re.search(r"\b(string|bytes)\b", params))

        if sensitive_names or dynamic_type:
            severity = "High" if sensitive_names else "Medium"
            if sensitive_names:
                description = (
                    "An event parameter name suggests personal or secret data. "
                    "Event data is generally publicly observable on-chain. "
                    "Confirm what the value contains."
                )
            else:
                description = (
                    "This event includes a dynamic string or bytes parameter. "
                    "Dynamic data is not automatically sensitive, but event "
                    "contents are publicly observable on-chain."
                )

            add(
                "PG-PRIV-001",
                severity,
                "Review public event data for sensitive values",
                description,
                "Emit only data intended to be public. Consider a non-sensitive "
                "identifier or commitment for indexing, and keep confidential "
                "values in an appropriate off-chain or confidential-computation design.",
                match.start(),
                source[match.start():match.end()],
            )




    # PG-PRIV-002: Public state variables can have generated getters.
    # Handles basic types, mappings, and arrays.
    public_state_pattern = (
        r"\b"
        r"(?:(?:mapping\s*\([^;]*?\)|"
        r"(?:string|bytes(?:\d+)?|uint\d*|int\d*|address|bool|"
        r"[A-Za-z_]\w*)"
        r"(?:\s*\[[^\]]*\])*)"
        r")\s+"
        r"public\s+"
        r"(?:(?:constant|immutable)\s+)?"
        r"(\w+)\s*(?:[;=])"
    )

    for match in re.finditer(public_state_pattern, code):
        name = match.group(1)

        if re.search(
            r"secret|private|password|email|phone|ssn|salary|"
            r"personalData|userData|position|balancePrivate",
            name,
            re.IGNORECASE,
        ):
            add(
                "PG-PRIV-002",
                "Medium",
                "Review public state for sensitive data",
                f'The public state variable "{name}" may expose its value '
                "through a generated getter. The name is only a heuristic; "
                "confirm what the value represents.",
                "Do not store confidential plaintext in public chain state. "
                "Solidity visibility does not encrypt blockchain storage.",
                match.start(),
                source[match.start():match.end()],
            )
  
   
    # PG-PRIV-003: Solidity private visibility is not encryption.
    # Review basic types, mappings, and arrays with sensitive-looking names.
    private_state_pattern = (
        r"\b"
        r"(?P<type>mapping\s*\([^;{}]*?\)|"
        r"(?:string|bytes(?:\d+)?|uint\d*|int\d*|address|bool|"
        r"[A-Za-z_]\w*)"
        r"(?:\s*\[[^\]]*\])*)"
        r"\s+private\s+"
        r"(?P<name>\w+)\b"
    )

    sensitive_private_name = re.compile(
        r"secret|password|privateKey|email|phone|ssn|salary|"
        r"personalData|userData|medicalRecord|homeAddress",
        re.IGNORECASE,
    )

    for match in re.finditer(private_state_pattern, code):
        name = match.group("name")

        if sensitive_private_name.search(name):
            add(
                "PG-PRIV-003",
                "Medium",
                'Solidity "private" does not provide confidentiality',
                f'The variable "{name}" uses Solidity private visibility. '
                "The name suggests potentially sensitive data, but the name "
                "alone cannot establish what the value contains. Solidity "
                "private visibility does not encrypt blockchain storage.",
                "Confirm what the variable stores. Do not rely on private "
                "visibility to protect confidential plaintext. Consider an "
                "appropriate encryption or confidential-computation design.",
                match.start(),
                source[match.start():match.end()],
            )


    # PG-PRIV-004: Possible hardcoded credentials.
    # Heuristic only: matching text does not prove a real secret exists.
    credential_pattern = re.compile(
        r"\b(?:apiKey|api_key|apiSecret|api_secret|password|passwd|"
        r"privateKey|private_key|secret|secretKey|secret_key|"
        r"accessToken|access_token|authToken|auth_token|token)"
        r"\s*[:=]\s*"
        r"""(["'])(?P<value>[^"'\\\n]{6,})\1""",
        re.IGNORECASE,
    )

    for match in credential_pattern.finditer(code):
        value = match.group("value")

        # Avoid reporting obvious placeholders as likely real credentials.
        if value.lower() in {
            "changeme",
            "change_me",
            "your_secret",
            "your_api_key",
            "example",
            "placeholder",
            "replace_me",
        }:
            continue

        add(
            "PG-PRIV-004",
            "High",
            "Possible hardcoded secret",
            "A credential-like variable is assigned a quoted string. "
            "This is a heuristic and cannot establish whether the value "
            "is a real, active, or sensitive credential.",
            "Check whether the value is a real credential. Remove real "
            "secrets from source code and rotate any exposed credential. "
            "Use an appropriate secret-management mechanism.",
            match.start(),
            source[match.start():match.end()],
        )



    # PG-PRIV-005: Review low-level storage writes involving sensitive values.
    # This is a source-level heuristic, not proof of a privacy vulnerability.
    sstore_pattern = re.compile(
        r"\bsstore\s*\(\s*"
        r"(?P<slot>[^,()]+)\s*,\s*"
        r"(?P<value>[^()]*?)\s*\)",
        re.IGNORECASE,
    )


    sensitive_storage_value = re.compile(
        r"(?:secret|password|privatekey|apikey|token|"
        r"useremail|email|phone|personaldata|userdata|"
        r"privatedata|medicalrecord)",
        re.IGNORECASE,
    )


    for match in sstore_pattern.finditer(code):
        value = match.group("value").strip()

        if sensitive_storage_value.search(value):
            add(
                "PG-PRIV-005",
                "Medium",
                "Review low-level storage writes involving sensitive values",
                "A low-level sstore call appears to write a value whose name "
                "suggests potentially sensitive data. This heuristic cannot "
                "determine the value's actual contents or whether the write "
                "is unsafe.",
                "Trace the value and storage slot. Confirm whether the data "
                "must be public. Blockchain storage is not confidential by "
                "default; use an appropriate cryptographic or "
                "confidential-computation design if secrecy is required.",
                match.start(),
                source[match.start():match.end()],
            )

    # PG-HZN-001: Review Vela de-anonymization authorization.
    deanon = re.search(
        r"\bDEANONYMIZATION\b|\bdeanonymiz\w*\b",
        code,
        re.IGNORECASE,
    )
    processor_call = re.search(
        r"\bsubmitRequest\s*\(|\bprocess_request\s*\(",
        code,
    )
    if deanon and processor_call:
        index = min(deanon.start(), processor_call.start())
        add(
            "PG-HZN-001",
            "Medium",
            "Review Vela de-anonymization authorization",
            "This source appears to reference a Vela de-anonymization workflow. "
            "Vela documentation describes authorization involving the "
            "AuthorityRegistry for the target application. This pattern cannot "
            "prove whether the authorization boundary is correctly enforced.",
            "Trace the request to the intended ProcessorEndpoint and confirm "
            "that the documented AuthorityRegistry authorization is enforced "
            "end-to-end. Test authorized and unregistered callers. A local "
            "caller-side check alone is not sufficient.",
            index,
            source[index:min(len(source), index + 240)],
        )

    # PG-HZN-002: Attestation and result-verification review.
    vela_terms = re.search(
        r"\b(?:vela|tee|enclave|attestation|attested)\b",
        code,
        re.IGNORECASE,
    )
    verification_terms = re.search(
        r"\b(?:attestation|attested|enclave|tee|signature|signer|verify|recover)\b",
        code,
        re.IGNORECASE,
    )
    if vela_terms and verification_terms:
        index = vela_terms.start()
        add(
            "PG-HZN-002",
            "Low",
            "Review Vela attestation and result verification",
            "The source appears to reference a TEE or attestation concept. "
            "Static source matching cannot establish whether attestation, "
            "signatures, freshness, and result-to-request binding are correctly "
            "verified. Verification may be delegated to another contract.",
            "Trace the full verification path. Confirm expected enclave or "
            "application measurements, signature or attestation validation, "
            "freshness and replay protections, and binding between the verified "
            "result and its request. Attestation does not prove application logic is correct.",
            index,
            source[index:min(len(source), index + 240)],
        )

    # PG-HZN-003: Mock or no-attestation components need deployment review.
    no_attestation = re.search(
        r"\b(?:NoAttestationTeeAuthenticator|NoAttestationAuthenticator|"
        r"MockTeeAuthenticator|MockAttestation)\b",
        code,
        re.IGNORECASE,
    )
    if no_attestation:
        add(
            "PG-HZN-003",
            "Medium",
            "Development or mock attestation component detected",
            "A name matching a no-attestation or mock authenticator appears "
            "in code. This can be valid in tests, but may be a production risk "
            "if deployed as a trust boundary.",
            "Confirm this component is restricted to development and tests. "
            "Verify the actual deployed authenticator address and configuration "
            "independently.",
            no_attestation.start(),
            source[no_attestation.start():min(len(source), no_attestation.end() + 100)],
        )

    # PG-HZN-004: Potentially sensitive report data in public outputs.
    report_terms = re.search(
        r"\b(?:deanonymiz\w*|complianceReport|auditReport|privateReport)\b",
        code,
        re.IGNORECASE,
    )
    public_output = re.search(
        r"\b(?:emit\s+\w+\s*\([^)]*(?:report|record|data|result)[^)]*\)"
        r"|event\s+\w+\s*\([^)]*(?:report|record|data|result)[^)]*\))",
        code,
        re.IGNORECASE | re.DOTALL,
    )
    if report_terms and public_output:
        index = public_output.start()
        add(
            "PG-HZN-004",
            "Medium",
            "Review public outputs in a confidential reporting flow",
            "The source references a de-anonymization or compliance-report "
            "concept and appears to emit report-like data. This may be intended, "
            "but public event and transaction data can reveal values expected "
            "to remain confidential.",
            "Check whether emitted fields are only public identifiers or status "
            "values. Keep report plaintext off-chain and use the documented "
            "confidential or encrypted-report design where applicable.",
            index,
            source[index:public_output.end()],
        )

    # PG-REVIEW-001: A review prompt, not proof of missing authorization.
    function_pattern = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)\s*([^{;]*)\{",
        re.MULTILINE,
    )
    for match in function_pattern.finditer(code):
        body_start = match.end()
        depth = 1
        cursor = body_start

        while cursor < len(code) and depth:
            if code[cursor] == "{":
                depth += 1
            elif code[cursor] == "}":
                depth -= 1
            cursor += 1

        body = code[body_start:max(body_start, cursor - 1)]
        header = match.group(2)

        writes = re.search(
            r"\b(?:emit\s+\w+|sstore\s*\(|"
            r"\w+\s*\[[^\]]+\]\s*=|\w+\s*=\s*[^=])",
            body,
        )
        authorization = re.search(
            r"\b(?:onlyOwner|onlyAdmin|onlyRole|_checkRole|hasRole)\b"
            r"|require\s*\(\s*msg\.sender",
            header + " " + body,
        )

        if writes and not authorization:
            add(
                "PG-REVIEW-001",
                "Medium",
                "Review write-function access control",
                f'Function "{match.group(1)}" appears to write state or emit data, '
                "but this simple check did not find a common authorization pattern. "
                "Permissionless functions or authorization enforced by another "
                "contract can trigger this warning.",
                "Review the intended authorization model and test who can call "
                "the function. If another contract or role system enforces "
                "authorization, document and test that boundary.",
                match.start(),
                source[match.start():match.end()],
            )

    # Deduplicate findings by rule, line, and title.
    unique: dict[tuple[str, int, str], dict[str, Any]] = {}
    for finding in results:
        key = (
            finding["rule_id"],
            finding["line"],
            finding["title"],
        )
        unique[key] = finding

    return sorted(
        unique.values(),
        key=lambda item: (
            severity_rank(item["severity"]),
            item["line"],
            item["rule_id"],
        ),
    )


def run_slither(source: str, filename: str) -> dict[str, Any]:
    """Run Slither on a temporary source file. Imports may need project context."""
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", filename)
    if not safe_name.endswith(".sol"):
        safe_name = "Contract.sol"

    with tempfile.TemporaryDirectory(prefix="privacyguard-") as tmp:
        file_path = Path(tmp) / safe_name
        file_path.write_text(source, encoding="utf-8")

        try:
            proc = subprocess.run(
                ["slither", str(file_path), "--json", "-"],
                capture_output=True,
                text=True,
                timeout=45,
                cwd=tmp,
                env={**os.environ, "NO_COLOR": "1"},
            )
        except FileNotFoundError:
            return {
                "available": False,
                "status": "not_installed",
                "findings": [],
                "message": "Slither is not available in this runtime.",
            }
        except subprocess.TimeoutExpired:
            return {
                "available": True,
                "status": "timeout",
                "findings": [],
                "message": "Slither timed out after 45 seconds.",
            }

        raw = proc.stdout.strip()
        start = raw.find("{")

        if start < 0:
            message = (
                proc.stderr or raw or "Slither produced no JSON output."
            )[-1800:]
            return {
                "available": True,
                "status": "compile_or_analysis_error",
                "findings": [],
                "message": message,
            }

        try:
            payload = json.loads(raw[start:])
        except json.JSONDecodeError:
            return {
                "available": True,
                "status": "compile_or_analysis_error",
                "findings": [],
                "message": (
                    proc.stderr or raw or "Could not parse Slither output."
                )[-1800:],
            }

        findings = []
        detectors = payload.get("results", {}).get("detectors", [])

        for detector in detectors:
            elements = detector.get("elements", [])
            first = elements[0] if elements else {}
            mapping = first.get("source_mapping", {})
            lines = mapping.get("lines") or []
            impact = (detector.get("impact") or "Informational").lower()

            if impact in {"high", "critical"}:
                severity = "High"
            elif impact in {"medium", "moderate"}:
                severity = "Medium"
            else:
                severity = "Low"

            check = detector.get("check", "slither")
            findings.append({
                "id": f"SLITHER-{check}-{len(findings)}",
                "rule_id": check,
                "severity": severity,
                "title": check.replace("-", " ").title(),
                "description": detector.get(
                    "description", "Slither reported a potential issue."
                ),
                "recommendation": (
                    "Review the Slither detector documentation and validate "
                    "the finding in the context of this contract."
                ),
                "line": lines[0] if lines else None,
                "snippet": "",
                "source": "Slither",
            })

        return {
            "available": True,
            "status": "ok",
            "findings": findings,
            "message": None,
        }


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "privacyguard-scanner",
        "version": APP_VERSION,
    }


@app.get("/api/rules")
def rules() -> dict[str, Any]:
    return {
        "version": APP_VERSION,
        "scope": (
            "Solidity source-level heuristics. This does not inspect Vela "
            "runtime/WASM execution or cryptographically verify TEE attestations."
        ),
        "rules": [
            {
                "id": "PG-PRIV-001",
                "title": "Review public event data for sensitive values",
                "severity": "Medium/High",
                "purpose": "Flags dynamic event parameters and sensitive-looking names.",
            },
            {
                "id": "PG-PRIV-002",
                "title": "Review public state for sensitive data",
                "severity": "Medium",
                "purpose": "Flags public state variable names that may indicate sensitive data.",
            },
            {
                "id": "PG-PRIV-003",
                "title": "Solidity private does not provide confidentiality",
                "severity": "Medium",
                "purpose": "Explains that private visibility does not encrypt storage.",
            },
            {
                "id": "PG-PRIV-004",
                "title": "Possible hardcoded secret",
                "severity": "High",
                "purpose": "Flags simple hardcoded credential-like assignments.",
            },
            {
                "id": "PG-PRIV-005",
                "title": "Review low-level storage writes involving sensitive values",
                "severity": "Medium",
                "purpose": "Flags sstore calls whose value expression contains sensitive-looking names.",
            },
            {
                "id": "PG-HZN-001",
                "title": "Review Vela de-anonymization authorization",
                "severity": "Medium",
                "purpose": "Prompts review of the AuthorityRegistry and ProcessorEndpoint authorization path.",
            },
            {
                "id": "PG-HZN-002",
                "title": "Review Vela attestation and result verification",
                "severity": "Low",
                "purpose": "Prompts review of attestation, freshness, and result binding.",
            },
            {
                "id": "PG-HZN-003",
                "title": "Development or mock attestation component detected",
                "severity": "Medium",
                "purpose": "Flags known mock or no-attestation authenticator names.",
            },
            {
                "id": "PG-HZN-004",
                "title": "Review public outputs in a confidential reporting flow",
                "severity": "Medium",
                "purpose": "Flags possible report-like public output in confidential workflows.",
            },
            {
                "id": "PG-REVIEW-001",
                "title": "Review write-function access control",
                "severity": "Medium",
                "purpose": "Review prompt; legitimate permissionless functions may trigger it.",
            },
        ],
    }


@app.post("/api/scan")
def scan(request: ScanRequest) -> dict[str, Any]:
    source = request.source

    if not source.strip():
        raise HTTPException(
            status_code=400,
            detail="Paste Solidity source code before scanning.",
        )

    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Source is too large. Limit is {MAX_SOURCE_BYTES} bytes.",
        )

    if not re.search(
        r"\bpragma\s+solidity\b|\bcontract\s+\w+|"
        r"\binterface\s+\w+|\blibrary\s+\w+",
        source,
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "This does not look like Solidity source. Include a contract, "
                "interface, library, or Solidity pragma."
            ),
        )

    heuristic_findings = privacy_checks(source)
    slither = run_slither(source, request.filename)
    all_findings = heuristic_findings + slither["findings"]

    all_findings.sort(
        key=lambda item: (
            severity_rank(item["severity"]),
            item.get("line") or 999999,
            item["rule_id"],
        )
    )

    counts = {
        level: sum(
            1 for finding in all_findings
            if finding["severity"] == level
        )
        for level in ("High", "Medium", "Low")
    }

    return {
        "version": APP_VERSION,
        "filename": request.filename,
        "lines_analyzed": len(source.splitlines()),
        "finding_count": len(all_findings),
        "counts": counts,
        "findings": all_findings,
        "analysis": {
            "heuristics": "completed",
            "slither_status": slither["status"],
            "slither_message": slither["message"],
            "slither_findings": len(slither["findings"]),
        },
        "notice": (
            "Prototype findings may include false positives and false negatives. "
            "They are not proof of vulnerability, safety, or privacy."
        ),
    }

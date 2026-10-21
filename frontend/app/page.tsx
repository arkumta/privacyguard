
"use client";

import { useMemo, useState } from "react";

type Severity = "High" | "Medium" | "Low";

type Finding = {
  id: string;
  rule_id: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  line: number | null;
  snippet: string;
  source: string;
};

type ScanResponse = {
  filename: string;
  lines_analyzed: number;
  finding_count: number;
  counts: Record<Severity, number>;
  findings: Finding[];
  analysis: {
    slither_status: string;
    slither_message: string | null;
    slither_findings: number;
  };
  notice: string;
};

type Guidance = {
  why: string;
  verify: string[];
  remediation: string;
};

const sample = `// Example contract intentionally contains patterns for demonstration.
// Do not deploy this example.
pragma solidity ^0.8.20;

contract ExampleRewards {
    address public admin;
    mapping(address => uint256) public userRewards;
    event UserRewarded(address indexed user, uint256 amount, string email);

    constructor() {
        admin = msg.sender;
    }

    function rewardUser(address user, uint256 amount, string calldata email) external {
        userRewards[user] = amount;
        emit UserRewarded(user, amount, email);
    }

    function setSecret(bytes32 secret) external {
        // A variable name does not make on-chain data secret.
        assembly {
            sstore(0, secret)
        }
    }

    function withdraw(address payable recipient, uint256 amount) external {
        require(msg.sender == admin, "not admin");
        recipient.transfer(amount);
    }
}`;

const filters = ["All", "High", "Medium", "Low"] as const;
type Filter = (typeof filters)[number];

function getGuidance(f: Finding): Guidance {
  switch (f.rule_id) {
    case "PG-PRIV-001":
      return {
        why:
          "Event data is recorded in transaction logs and may be observable by blockchain users and indexing services. A sensitive-looking field name is a clue to investigate, not proof that the value is confidential.",
        verify: [
          "Inspect every event parameter and identify whether it contains personal, confidential, or linkable information.",
          "Check whether emitted values can be associated with a wallet, person, or off-chain identity.",
          "Confirm whether each value needs to be published permanently.",
        ],
        remediation:
          "Avoid emitting confidential plaintext. Emit only the minimum data needed. Where appropriate, consider commitments, opaque identifiers, or a carefully designed off-chain disclosure flow.",
      };

    case "PG-PRIV-002":
      return {
        why:
          "A public state variable normally receives a generated getter. Blockchain state can be inspected independently of that getter, so Solidity visibility does not provide confidentiality.",
        verify: [
          "Confirm what the variable actually stores; its name alone does not establish sensitivity.",
          "Inspect assignments and all code paths that write to the variable.",
          "Check whether the value or its relationship to a wallet could reveal personal or confidential information.",
        ],
        remediation:
          "Do not store confidential plaintext in public chain state. Store only data that can safely be public. Evaluate encryption or a suitable confidential-computation design when the application requires confidentiality.",
      };

    case "PG-PRIV-003":
      return {
        why:
          "The Solidity private keyword restricts access through Solidity-level contract interfaces; it does not encrypt storage or hide blockchain data from observers.",
        verify: [
          "Identify the actual value stored in the variable.",
          "Check whether storage slots, transaction inputs, events, or contract behavior expose the value.",
          "Determine whether the application threat model requires the value to remain confidential from chain observers.",
        ],
        remediation:
          "Do not rely on private visibility for confidentiality. Consider an appropriate cryptographic design, such as encryption or commitments, and account for keys, metadata, and public transaction inputs.",
      };

    case "PG-PRIV-004":
      return {
        why:
          "A hardcoded credential or secret may be recoverable from deployed bytecode, transaction data, or public source code. The pattern match must be confirmed against the actual value.",
        verify: [
          "Inspect the matched assignment and determine whether the value is a real credential or only a placeholder.",
          "Check whether the value has ever been deployed, committed, or otherwise exposed.",
          "If a real credential was exposed, assess its scope and whether it remains valid.",
        ],
        remediation:
          "Remove credentials from contract source and rotate any real exposed secret. Use an appropriate secret-management mechanism off-chain; never assume an on-chain value is confidential.",
      };

    case "PG-PRIV-005":
      return {
        why:
          "A low-level sstore operation writes directly to a storage slot. If the value contains confidential information, that data may be observable on-chain. A sensitive-looking variable name is only a clue; this finding does not prove a privacy vulnerability.",
        verify: [
          "Trace the value passed to sstore and determine what it actually contains.",
          "Identify the storage slot and check whether the write overlaps with other contract state.",
          "Determine whether the value must remain confidential and whether it can be recovered from public chain data.",
        ],
        remediation:
          "Do not store confidential plaintext directly in public blockchain storage. If confidentiality is required, evaluate a suitable cryptographic or confidential-computation design. Do not treat every sstore operation as unsafe.",
      };

    case "PG-HZN-001":
      return {
        why:
          "A de-anonymization workflow may expose protected information if the request path does not enforce the intended authority and application-specific permissions. This heuristic does not prove an authorization flaw.",
        verify: [
          "Trace the complete request path and identify where authorization is enforced.",
          "Verify that the caller is authorized for the target application and requested operation.",
          "Check denial paths, role changes, and whether authorization can be bypassed through an alternate entry point.",
        ],
        remediation:
          "Enforce authorization at the appropriate trusted boundary. Validate the caller, application, and requested operation according to the actual Vela integration and its documented trust model.",
      };

    case "PG-HZN-002":
      return {
        why:
          "Attestation-related code may need to verify the expected enclave identity and measurement. An attestation alone does not prove that application logic is correct or that a result is bound to the right request.",
        verify: [
          "Determine what the attestation proves and which trusted component verifies it.",
          "Check freshness, replay resistance, and binding to the relevant request and result.",
          "Review failure handling and the assumptions made about the enclave, verifier, and application.",
        ],
        remediation:
          "Follow the integration's documented attestation-verification procedure. Validate freshness and request/result binding where required, and document what the attestation does and does not establish.",
      };

    case "PG-HZN-003":
      return {
        why:
          "A mock or no-attestation component may bypass checks that are expected in production. Its name alone does not establish whether the component is reachable in a deployed build.",
        verify: [
          "Locate the component definition and all places where it is instantiated or selected.",
          "Determine whether it is limited to tests or development configurations.",
          "Inspect deployment configuration and confirm the production path uses the intended verifier.",
        ],
        remediation:
          "Keep mock authenticators confined to controlled tests. Ensure production configuration selects the intended verification implementation and fails safely when required verification is unavailable.",
      };

    case "PG-HZN-004":
      return {
        why:
          "A public report or event in a confidential workflow may disclose information that the application intended to keep private. The heuristic cannot determine the sensitivity of the actual output.",
        verify: [
          "Inspect the report fields, event parameters, and returned values.",
          "Determine whether the output reveals identities, private inputs, or sensitive conclusions.",
          "Check whether the same information can be linked with public chain data or external datasets.",
        ],
        remediation:
          "Minimize public output and disclose only what the application requires. Consider a commitment or a controlled disclosure mechanism when publishing the underlying information is unnecessary.",
      };

    case "PG-REVIEW-001":
      return {
        why:
          "A function that changes state may need access control, but permissionless state changes can also be intentional. This review prompt is not proof of a missing authorization check.",
        verify: [
          "Identify the intended callers and the business rules governing the operation.",
          "Check ownership, role checks, signatures, or other authorization mechanisms where needed.",
          "Test unauthorized calls and confirm that legitimate permissionless operations remain available.",
        ],
        remediation:
          "Add an appropriate authorization check only when the operation requires one. Preserve intentionally permissionless behavior and document its security assumptions.",
      };

    default:
      return {
        why:
          "This finding needs to be interpreted in the context of the matched source and the detector that produced it.",
        verify: [
          "Read the full finding description and inspect the cited source location.",
          "Reproduce the condition with a focused test where possible.",
          "Determine whether the finding applies to the deployed configuration and intended behavior.",
        ],
        remediation:
          "Use the recommendation supplied by the detector as the starting point. Validate the proposed change with tests and review any effect on intended behavior.",
      };
  }
}

function isSlitherFinding(f: Finding) {
  return (
    f.source.toLowerCase().includes("slither") ||
    f.rule_id.toLowerCase().startsWith("slither-")
  );
}

export default function Home() {
  const [source, setSource] = useState(sample);
  const [report, setReport] = useState<ScanResponse | null>(null);
  const [filter, setFilter] = useState<Filter>("All");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const visibleFindings = useMemo(
    () =>
      (report?.findings ?? []).filter(
        (finding) => filter === "All" || finding.severity === filter
      ),
    [report, filter]
  );

  async function runScan() {
    setLoading(true);
    setError("");
    setReport(null);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source, filename: "Contract.sol" }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Scan failed. Check that the scanner backend is running."
        );
      }

      setReport(data as ScanResponse);
      setFilter("All");
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "An unexpected error occurred."
      );
    } finally {
      setLoading(false);
    }
  }

  function exportReport() {
    if (!report) return;

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = "privacyguard-report.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  const lines = source ? source.split("\n").length : 0;

  return (
    <main className="wrap">
      <header className="top">
        <div className="brand">
          <div className="logo">P</div>
          <div>
            <h1>
              PrivacyGuard <span style={{ color: "var(--green)" }}>/</span>{" "}
              Horizen
            </h1>
            <div className="sub">
              Privacy-focused smart contract review · Development build
            </div>
          </div>
        </div>
        <span className="pill">Prototype v0.1</span>
      </header>

      <section className="hero">
        <div className="eyebrow">Developer security toolkit</div>
        <h2>Find potential privacy risks before they reach mainnet.</h2>
        <p>
          Analyze Solidity source with privacy-specific heuristics and
          established static analysis. Review the evidence, understand the risk,
          and get practical next steps.
        </p>
      </section>

      <div className="layout">
        <section className="panel">
          <div className="panelHead">
            <div>
              <h3>Solidity source</h3>
              <div className="small">
                Paste code or load the included example
              </div>
            </div>
            <button className="ghost" onClick={() => setSource(sample)}>
              Load sample
            </button>
          </div>

          <div className="panelBody">
            <textarea
              aria-label="Solidity source code"
              spellCheck={false}
              value={source}
              onChange={(e) => setSource(e.target.value)}
            />

            <div className="editorFoot">
              <span className="small">
                {lines} lines · {source.length} characters
              </span>
              <div className="actions">
                <button
                  className="secondary"
                  onClick={() => {
                    setSource("");
                    setReport(null);
                    setError("");
                  }}
                >
                  Clear
                </button>
                <button
                  className="primary"
                  disabled={loading || !source.trim()}
                  onClick={runScan}
                >
                  {loading ? "Scanning…" : "Run privacy scan ↗"}
                </button>
              </div>
            </div>

            <div className="notice">
              <b>Local development:</b> source is sent to the scanner backend
              running in your local Docker environment. This starter does not
              include a hosted service or database.
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panelHead">
            <div>
              <h3>Scan report</h3>
              <div className="small">
                {report
                  ? `${report.finding_count} findings · ${report.lines_analyzed} lines analyzed`
                  : "Run a scan to see findings"}
              </div>
            </div>
            <span className="small">Local API</span>
          </div>

          <div className="panelBody">
            {error && <div className="error">{error}</div>}

            <div className="summary">
              <div className="stat high">
                <strong>{report ? report.counts.High : "—"}</strong>
                <span>High priority</span>
              </div>
              <div className="stat medium">
                <strong>{report ? report.counts.Medium : "—"}</strong>
                <span>Review</span>
              </div>
              <div className="stat low">
                <strong>{report ? report.counts.Low : "—"}</strong>
                <span>Informational</span>
              </div>
            </div>

            <div className="score">
              <div>
                <small>Initial assessment</small>
                <strong>
                  {!report
                    ? "Not scanned"
                    : report.counts.High
                      ? "Needs attention"
                      : report.counts.Medium
                        ? "Review recommended"
                        : "No rule triggered"}
                </strong>
                <small>
                  {!report
                    ? "Run a scan to generate an initial review."
                    : "This is not a security or privacy guarantee."}
                </small>
              </div>
              <div className="scoreTag">
                {loading ? "Scanning" : report ? "Complete" : "Awaiting scan"}
              </div>
            </div>

            {report && (
              <>
                <div className="filters">
                  {filters.map((item) => (
                    <button
                      key={item}
                      className={`filter ${filter === item ? "active" : ""}`}
                      onClick={() => setFilter(item)}
                    >
                      {item === "All"
                        ? "All findings"
                        : item === "Medium"
                          ? "Review"
                          : item === "Low"
                            ? "Info"
                            : item}
                    </button>
                  ))}
                  <button className="filter" onClick={exportReport}>
                    Export JSON ↓
                  </button>
                </div>

                <div className="small scan-status">
                  Slither: {report.analysis.slither_status.replaceAll("_", " ")}
                  {report.analysis.slither_message
                    ? ` — ${report.analysis.slither_message.slice(0, 220)}`
                    : ` · ${report.analysis.slither_findings} finding(s)`}
                </div>
              </>
            )}

            {!report && !loading && (
              <div className="empty">
                No report yet.
                <br />
                Load the sample contract and run a scan.
              </div>
            )}

            {loading && (
              <div className="empty">
                Analyzing source code…
                <br />
                The first scan can take a little longer.
              </div>
            )}

            {report && visibleFindings.length === 0 && (
              <div className="empty">No findings in this filter.</div>
            )}

            {visibleFindings.map((f) => {
              const guidance = getGuidance(f);
              const slitherFinding = isSlitherFinding(f);

              return (
                <details className="finding" key={f.id}>
                  <summary>
                    <span className={`severity sev${f.severity}`}>
                      {f.severity}
                    </span>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div className="findingTitle">{f.title}</div>
                      <div className="findingMeta">
                        {f.rule_id} · {f.line ? `Line ${f.line}` : "Line unavailable"} · {f.source}
                      </div>
                    </div>
                    <span className="chev">⌄</span>
                  </summary>

                  <div className="findingBody">
                    <div className="findingType">
                      <span className="detailLabel">Detection source</span>
                      <span className="sourceTag">
                        {slitherFinding
                          ? "Slither static analysis"
                          : "PrivacyGuard heuristic"}
                      </span>
                    </div>

                    <section className="detailSection">
                      <h4>What was detected</h4>
                      <p>{f.description}</p>
                    </section>

                    <section className="detailSection">
                      <h4>Why this matters</h4>
                      <p>{guidance.why}</p>
                    </section>

                    {f.snippet && (
                      <section className="detailSection">
                        <h4>Source evidence</h4>
                        <div className="code">
                          {f.line ? `L${f.line}: ` : ""}
                          {f.snippet}
                        </div>
                      </section>
                    )}

                    <section className="detailSection">
                      <h4>What to verify</h4>
                      <ul className="verifyList">
                        {guidance.verify.map((step, index) => (
                          <li key={index}>{step}</li>
                        ))}
                      </ul>
                    </section>

                    <section className="fix">
                      <h4>Recommended remediation</h4>
                      <p>{f.recommendation}</p>
                      <p>{guidance.remediation}</p>
                    </section>

                    <div className="findingDisclaimer">
                      {slitherFinding
                        ? "Static-analysis result: validate the detector output against the source and the relevant tool documentation."
                        : "Heuristic review prompt: confirm the finding manually. A pattern match alone does not establish a vulnerability."}
                    </div>
                  </div>
                </details>
              );
            })}

            <div className="notice">
              <b>Important:</b> results can include false positives and false
              negatives. This prototype is not a replacement for tests, expert
              review, or a professional audit.
            </div>
          </div>
        </section>
      </div>

      <footer className="footer">
        <span>PrivacyGuard · Open-source prototype</span>
        <span>Local development build · No hosted database</span>
      </footer>
    </main>
  );
}

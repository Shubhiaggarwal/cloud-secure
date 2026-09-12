import React, { useState } from "react";

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEVERITY_COLORS = {
  CRITICAL: "#d32f2f",
  HIGH: "#f57c00",
  MEDIUM: "#f9a825",
  LOW: "#546e7a",
};

export default function FindingsTable({ findings, onAskAbout }) {
  const [filter, setFilter] = useState("ALL");

  const visible =
    filter === "ALL" ? findings : findings.filter((f) => f.severity === filter);

  const sorted = [...visible].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <div className="findings-panel">
      <div className="filter-row">
        {["ALL", ...SEVERITY_ORDER].map((s) => (
          <button
            key={s}
            className={`filter-chip ${filter === s ? "active" : ""}`}
            onClick={() => setFilter(s)}
          >
            {s}
          </button>
        ))}
      </div>

      {sorted.length === 0 && <p className="empty">No findings in this category.</p>}

      {sorted.map((f) => (
        <div key={f.id} className="finding-card">
          <div className="finding-header">
            <span
              className="severity-badge"
              style={{ background: SEVERITY_COLORS[f.severity] || "#999" }}
            >
              {f.severity}
            </span>
            <span className="finding-resource">
              ({f.service}/{f.rule_id}) {f.resource}
            </span>
          </div>
          <p>
            <strong>Issue:</strong> {f.issue}
          </p>
          <p>
            <strong>Impact:</strong> {f.impact}
          </p>
          <p>
            <strong>Recommendation:</strong> {f.recommendation}
          </p>
          {f.mitre && (
            <p className="mitre">
              <strong>MITRE ATT&amp;CK:</strong> {f.mitre}
            </p>
          )}
          <button className="ask-btn" onClick={() => onAskAbout(f)}>
            Ask the assistant how to fix this
          </button>
        </div>
      ))}
    </div>
  );
}

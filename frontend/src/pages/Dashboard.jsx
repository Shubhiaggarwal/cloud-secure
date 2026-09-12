import React, { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { api, clearToken } from "../api.js";
import ScoreCard from "../components/ScoreCard.jsx";
import FindingsTable from "../components/FindingsTable.jsx";
import ChatWidget from "../components/ChatWidget.jsx";

const POLL_INTERVAL_MS = 2000;

export default function Dashboard() {
  const navigate = useNavigate();

  const [accounts, setAccounts] = useState([]);
  const [selectedAccountId, setSelectedAccountId] = useState(null);
  const [scan, setScan] = useState(null); // full ScanOut, or null
  const [scanning, setScanning] = useState(false);
  const [showAddAccount, setShowAddAccount] = useState(false);
  const [presetQuestion, setPresetQuestion] = useState(null);
  const [error, setError] = useState("");

  const loadAccounts = useCallback(async () => {
    const list = await api.listAccounts();
    setAccounts(list);
    if (list.length && !selectedAccountId) {
      setSelectedAccountId(list[0].id);
    }
  }, [selectedAccountId]);

  useEffect(() => {
    loadAccounts().catch((e) => setError(e.message));
  }, [loadAccounts]);

  // Load the most recent scan for the selected account, if any.
  useEffect(() => {
    if (!selectedAccountId) return;
    setScan(null);
    api
      .listScansForAccount(selectedAccountId)
      .then((scans) => {
        if (scans.length) return api.getScan(scans[0].id).then(setScan);
      })
      .catch((e) => setError(e.message));
  }, [selectedAccountId]);

  // Poll while a scan is running.
  useEffect(() => {
    if (!scan || scan.status === "complete" || scan.status === "failed") return;
    const interval = setInterval(async () => {
      const updated = await api.getScan(scan.id);
      setScan(updated);
      if (updated.status === "complete" || updated.status === "failed") {
        setScanning(false);
      }
    }, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [scan]);

  async function handleScanNow() {
    if (!selectedAccountId) return;
    setError("");
    setScanning(true);
    try {
      const summary = await api.triggerScan(selectedAccountId);
      const full = await api.getScan(summary.id);
      setScan(full);
    } catch (e) {
      setError(e.message);
      setScanning(false);
    }
  }

  function handleLogout() {
    clearToken();
    navigate("/login");
  }

  function askAboutFinding(finding) {
    setPresetQuestion(
      `How do I fix this finding: ${finding.service}/${finding.rule_id} on ${finding.resource} - "${finding.issue}"?`
    );
  }

  const selectedAccount = accounts.find((a) => a.id === selectedAccountId);

  return (
    <div className="app-layout">
      <header className="topbar">
        <h1>Cloud Security Posture Manager</h1>
        <button className="logout-btn" onClick={handleLogout}>
          Log out
        </button>
      </header>

      <div className="main-body single-column">
        <div className="content-column full-width">
          <section className="account-bar">
            <label>AWS Account:</label>
            <select
              value={selectedAccountId || ""}
              onChange={(e) => setSelectedAccountId(Number(e.target.value))}
            >
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} {a.demo_mode ? "(demo)" : ""}
                </option>
              ))}
            </select>
            <button onClick={() => setShowAddAccount((v) => !v)}>+ Add account</button>
            <button onClick={handleScanNow} disabled={!selectedAccountId || scanning}>
              {scanning ? "Scanning..." : "Scan Now"}
            </button>
          </section>

          {showAddAccount && (
            <AddAccountForm
              onCreated={() => {
                setShowAddAccount(false);
                loadAccounts();
              }}
            />
          )}

          {error && <div className="error">{error}</div>}

          {scan && scan.status === "failed" && (
            <div className="error">Scan failed: {scan.error_message}</div>
          )}

          {scan && scan.status === "complete" && (
            <>
              <div className="summary-row">
                <ScoreCard score={scan.security_score} />
                <div className="summary-text">
                  <p>
                    Scanned <strong>{selectedAccount?.name}</strong> at{" "}
                    {new Date(scan.finished_at).toLocaleString()}
                  </p>
                  <p>{scan.findings.length} total findings</p>
                </div>
              </div>
              <FindingsTable findings={scan.findings} onAskAbout={askAboutFinding} />
            </>
          )}

          {(!scan || scan.status === "pending" || scan.status === "running") && (
            <p className="empty">
              {scanning || (scan && scan.status !== "complete")
                ? "Scanning your AWS account for misconfigurations..."
                : "No scan yet. Click \"Scan Now\" to check this account for misconfigurations."}
            </p>
          )}
        </div>

        <ChatWidget
          scanId={scan && scan.status === "complete" ? scan.id : null}
          presetQuestion={presetQuestion}
          onPresetConsumed={() => setPresetQuestion(null)}
        />
      </div>
    </div>
  );
}

function AddAccountForm({ onCreated }) {
  const [name, setName] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [externalId, setExternalId] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [demoMode, setDemoMode] = useState(true);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      await api.createAccount({
        name,
        role_arn: demoMode ? null : roleArn,
        external_id: demoMode ? null : externalId,
        region,
        demo_mode: demoMode,
      });
      onCreated();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="add-account-form" onSubmit={handleSubmit}>
      <h3>Add an AWS account</h3>
      <label>Friendly name</label>
      <input value={name} onChange={(e) => setName(e.target.value)} required />

      <label>
        <input type="checkbox" checked={demoMode} onChange={(e) => setDemoMode(e.target.checked)} />
        Demo mode (scan a seeded mock account, no real AWS access needed)
      </label>

      {!demoMode && (
        <>
          <label>IAM Role ARN</label>
          <input
            value={roleArn}
            onChange={(e) => setRoleArn(e.target.value)}
            placeholder="arn:aws:iam::123456789012:role/CSPMScannerRole"
            required
          />
          <label>External ID</label>
          <input value={externalId} onChange={(e) => setExternalId(e.target.value)} />
        </>
      )}

      <label>Region</label>
      <input value={region} onChange={(e) => setRegion(e.target.value)} />

      {error && <div className="error">{error}</div>}
      <button type="submit" disabled={saving}>
        {saving ? "Saving..." : "Add account"}
      </button>
    </form>
  );
}

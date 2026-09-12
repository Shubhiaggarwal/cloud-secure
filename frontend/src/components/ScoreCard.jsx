import React from "react";

function scoreColor(score) {
  if (score >= 90) return "#2e7d32";
  if (score >= 75) return "#66bb6a";
  if (score >= 50) return "#f9a825";
  return "#d32f2f";
}

function scoreLabel(score) {
  if (score >= 90) return "Excellent";
  if (score >= 75) return "Good";
  if (score >= 50) return "Needs Improvement";
  return "Critical Risk";
}

export default function ScoreCard({ score }) {
  if (score === null || score === undefined) return null;
  return (
    <div className="score-card" style={{ borderColor: scoreColor(score) }}>
      <div className="score-number" style={{ color: scoreColor(score) }}>
        {score}
      </div>
      <div className="score-label">{scoreLabel(score)}</div>
    </div>
  );
}

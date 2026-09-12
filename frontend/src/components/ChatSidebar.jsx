import React, { useEffect, useRef, useState } from "react";
import { api } from "../api.js";

/**
 * Always-visible AI Security Assistant panel. Scoped to whatever scan is
 * currently selected (scanId prop) - if there's no completed scan yet, it
 * still renders so the user knows it's there, just with a prompt to run a
 * scan first.
 *
 * `askAboutFinding` (optional) lets parent components (e.g. the findings
 * table's "Ask the assistant" button) push a pre-filled question in here.
 */
export default function ChatSidebar({ scanId, presetQuestion, onPresetConsumed }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [sessionId, setSessionId] = useState(null);
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  // Reset conversation when the active scan changes.
  useEffect(() => {
    setMessages([]);
    setSessionId(null);
  }, [scanId]);

  useEffect(() => {
    if (presetQuestion) {
      send(presetQuestion);
      onPresetConsumed?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [presetQuestion]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function send(text) {
    const message = (text ?? input).trim();
    if (!message || !scanId) return;

    setMessages((prev) => [...prev, { role: "user", text: message }]);
    setInput("");
    setLoading(true);

    try {
      const res = await api.chat({ scan_id: scanId, message, session_id: sessionId });
      setSessionId(res.session_id);
      setMessages((prev) => [...prev, { role: "assistant", text: res.reply }]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", text: `[Error contacting assistant: ${err.message}]` },
      ]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="chat-sidebar">
      <div className="chat-header">AI Security Assistant</div>

      {!scanId && (
        <div className="chat-empty">
          Run a scan to start chatting about your findings.
        </div>
      )}

      <div className="chat-messages">
        {messages.map((m, i) => (
          <div key={i} className={`chat-bubble ${m.role}`}>
            {m.text}
          </div>
        ))}
        {loading && <div className="chat-bubble assistant loading">Thinking...</div>}
        <div ref={bottomRef} />
      </div>

      <form
        className="chat-input-row"
        onSubmit={(e) => {
          e.preventDefault();
          send();
        }}
      >
        <input
          placeholder={scanId ? "Ask about your findings..." : "Run a scan first"}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={!scanId || loading}
        />
        <button type="submit" disabled={!scanId || loading}>
          Send
        </button>
      </form>
    </div>
  );
}

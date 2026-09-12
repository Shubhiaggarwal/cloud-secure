import React, { useEffect, useRef, useState } from "react";
import { api } from "../api.js";

/**
 * Floating "Ask the AI Assistant" button, bottom-right of the screen.
 * Clicking it opens a popup chat panel scoped to the current scan.
 * Same backend contract as ChatSidebar - just a different presentation
 * (popup instead of always-visible column).
 *
 * `openSignal` is a number/string that increments/changes each time a
 * parent wants to force the widget open with a preset question (e.g. the
 * "Ask the assistant how to fix this" button on a finding card).
 */
export default function ChatWidget({ scanId, presetQuestion, onPresetConsumed }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [sessionId, setSessionId] = useState(null);
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    setMessages([]);
    setSessionId(null);
  }, [scanId]);

  useEffect(() => {
    if (presetQuestion) {
      setOpen(true);
      send(presetQuestion);
      onPresetConsumed?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [presetQuestion]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, open]);

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
    <>
      {open && (
        <div className="chat-popup">
          <div className="chat-popup-header">
            <span>AI Security Assistant</span>
            <button className="chat-popup-close" onClick={() => setOpen(false)}>
              &times;
            </button>
          </div>

          {!scanId && (
            <div className="chat-empty">Run a scan to start chatting about your findings.</div>
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
      )}

      <button
        className="chat-fab"
        onClick={() => setOpen((v) => !v)}
        title="Ask the AI Security Assistant"
      >
        {open ? "\u2715" : "\uD83D\uDCAC"}
      </button>
    </>
  );
}

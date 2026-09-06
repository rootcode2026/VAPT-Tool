"use client";

import { useCallback, useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import LoadingState from "@/components/ui/LoadingState";
import ErrorState from "@/components/ui/ErrorState";
import EmptyState from "@/components/ui/EmptyState";
import { useProjectContext } from "@/lib/project-context";
import { createConversation, listConversations, postMessage, getAIStatus, queryAI } from "@/lib/api/ai";

export default function AIPage() {
  const { selectedProjectId, status } = useProjectContext();
  const [conversations, setConversations] = useState([]);
  const [selected, setSelected] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [aiStatus, setAIStatus] = useState(null);
  const [sending, setSending] = useState(false);

  const load = useCallback(async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    try {
      const [statusRes, convRes] = await Promise.all([
        getAIStatus().catch(() => ({ enabled: false })),
        listConversations(selectedProjectId).catch(() => ({ items: [] })),
      ]);
      setAIStatus(statusRes);
      setConversations(convRes.items || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedProjectId]);

  useEffect(() => {
    if (status === "ready" && selectedProjectId) load();
  }, [status, selectedProjectId, load]);

  async function handleNewConversation() {
    try {
      const conv = await createConversation(selectedProjectId, "New Investigation");
      setConversations((prev) => [conv, ...prev]);
      setSelected(conv);
      setMessages([]);
    } catch (e) {
      setError(e.message);
    }
  }

  async function handleSend() {
    if (!input.trim() || !selected) return;
    const prompt = input.trim();
    setInput("");
    setSending(true);
    // optimistic user message
    setMessages((prev) => [...prev, { role: "user", content: prompt }]);
    try {
      const res = await postMessage(selected.id, prompt);
      setMessages((prev) => [...prev, { role: "assistant", content: res.content, confidence: res.confidence, evidence: res.evidence }]);
    } catch (e) {
      setMessages((prev) => [...prev, { role: "assistant", content: `Error: ${e.message}`, confidence: "low" }]);
    } finally {
      setSending(false);
    }
  }

  async function handleQuickQuery(q) {
    if (!selectedProjectId) return;
    setSending(true);
    setMessages((prev) => [...prev, { role: "user", content: q }]);
    try {
      const res = await queryAI(selectedProjectId, q);
      setMessages((prev) => [...prev, { role: "assistant", content: res.answer, confidence: res.confidence, evidence: res.evidence }]);
    } catch (e) {
      setMessages((prev) => [...prev, { role: "assistant", content: `Error: ${e.message}` }]);
    } finally {
      setSending(false);
    }
  }

  if (status === "loading") return <LoadingState message="Loading project..." />;
  if (!selectedProjectId) return <EmptyState title="No project" description="Select project" />;
  if (loading) return <div><PageHeader title="AI Security Analyst" description="Evidence-grounded analyst assistant" /><LoadingState message="Loading AI..." /></div>;

  return (
    <div className="space-y-6">
      <PageHeader title="AI Security Analyst" description="Assistant on top of deterministic pipeline — explains posture, findings, attack paths, remediation (read-only, advisory)" />
      {aiStatus && !aiStatus.enabled ? <div className="rounded border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">AI is disabled — set AI_ENABLED=true and configure provider. Platform works normally without AI.</div> : null}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-md border bg-surface p-4">
          <h3 className="text-sm font-semibold">Conversations</h3>
          <button type="button" onClick={handleNewConversation} className="mt-2 w-full rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground">New Conversation</button>
          <div className="mt-3 space-y-1">
            {conversations.length === 0 ? <p className="text-xs text-muted">No conversations.</p> : conversations.map((c) => (
              <button key={c.id} type="button" onClick={() => { setSelected(c); setMessages([]); }} className={`w-full rounded border px-2 py-1 text-left text-xs ${selected?.id === c.id ? "bg-surface-hover" : "bg-canvas"}`}>{c.title} <span className="text-muted">{new Date(c.created_at).toLocaleDateString()}</span></button>
            ))}
          </div>
          <div className="mt-4">
            <h4 className="text-xs font-semibold">Quick Queries</h4>
            <div className="mt-1 space-y-1">
              {["What are my most critical internet-exposed findings?", "Which findings are overdue?", "Show me SQL injection findings", "What changed this week?"].map((q) => (
                <button key={q} type="button" onClick={() => handleQuickQuery(q)} className="w-full rounded border bg-canvas px-2 py-1 text-left text-xs">{q}</button>
              ))}
            </div>
          </div>
        </div>
        <div className="lg:col-span-2 rounded-md border bg-surface p-4">
          {!selected ? <EmptyState title="Select conversation" description="Create or select a conversation to start investigation." /> : (
            <>
              <h3 className="text-sm font-semibold">{selected.title}</h3>
              <div className="mt-3 max-h-[400px] space-y-2 overflow-auto rounded border bg-canvas p-3">
                {messages.length === 0 ? <p className="text-xs text-muted">No messages. Ask about posture, findings, assets, attack paths, remediation.</p> : messages.map((m, i) => (
                  <div key={i} className={`rounded p-2 text-sm ${m.role === "user" ? "bg-primary/10" : "bg-surface"}`}>
                    <p className="text-xs font-medium">{m.role === "user" ? "You" : `Analyst ${m.confidence ? `(${m.confidence})` : ""}`}</p>
                    <p className="mt-1 whitespace-pre-wrap">{m.content}</p>
                    {m.evidence && m.evidence.length > 0 ? <p className="mt-1 text-xs text-muted">Evidence: {m.evidence.join(", ")}</p> : null}
                    {m.role === "assistant" ? <p className="mt-1 text-xs text-muted">FACT/ANALYSIS/RECOMMENDATION/UNKNOWN — verify via platform objects.</p> : null}
                  </div>
                ))}
                {sending ? <p className="text-xs text-muted">Analyst thinking...</p> : null}
              </div>
              <div className="mt-3 flex gap-2">
                <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleSend()} placeholder="Ask about security posture, findings, assets..." className="flex-1 rounded border bg-canvas px-2 py-1 text-sm" />
                <button type="button" onClick={handleSend} disabled={sending} className="rounded bg-primary px-3 py-1 text-sm font-medium text-primary-foreground disabled:opacity-50">Send</button>
              </div>
              <p className="mt-2 text-xs text-muted">AI is advisory; deterministic engines authoritative. Hallucination controls, citations [FINDING:id], bounded context, sanitized secrets.</p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

"use client";

import { useState } from "react";
import Link from "next/link";
import { forgotPassword } from "@/lib/api/auth";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setMessage("");
    setSubmitting(true);
    try {
      const res = await forgotPassword(email.trim());
      setMessage(res.message || "If an account exists for that email, you'll receive reset instructions.");
    } catch (err) {
      setError(err.message || "Unable to process request.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4 py-10">
      <div className="w-full max-w-md rounded-md border border-border bg-surface p-6 sm:p-8">
        <p className="text-center text-xs font-semibold uppercase tracking-wide text-muted">VAPT Platform</p>
        <h1 className="mt-2 text-center text-2xl font-semibold text-text">Forgot password</h1>
        <p className="mt-2 text-center text-sm text-muted">Enter your email and we will send reset instructions if your account exists.</p>
        <form className="mt-8 space-y-4" onSubmit={onSubmit}>
          <div>
            <label htmlFor="email" className="mb-1 block text-sm text-muted">Email</label>
            <input id="email" name="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
          </div>
          {message ? (<p className="text-sm text-success" role="status">{message}</p>) : null}
          {error ? (<p className="text-sm text-danger" role="alert">{error}</p>) : null}
          <button type="submit" disabled={submitting} className="w-full rounded-sm bg-primary px-3 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-60">{submitting ? "Sending..." : "Send reset link"}</button>
          <div className="text-center">
            <Link href="/login" className="text-sm text-primary hover:underline">Back to sign in</Link>
          </div>
        </form>
      </div>
    </div>
  );
}

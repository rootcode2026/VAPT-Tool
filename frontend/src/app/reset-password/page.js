"use client";

import { Suspense, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { resetPassword } from "@/lib/api/auth";
import LoadingState from "@/components/ui/LoadingState";

function ResetForm() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const token = searchParams.get("token") || "";
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setMessage("");
    if (!token) {
      setError("Invalid or missing reset token.");
      return;
    }
    setSubmitting(true);
    try {
      const res = await resetPassword(token, newPassword, confirmPassword);
      setMessage(res.message || "Password has been reset.");
      setTimeout(() => router.replace("/login"), 1500);
    } catch (err) {
      setError(err.message || "Unable to reset password.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4 py-10">
      <div className="w-full max-w-md rounded-md border border-border bg-surface p-6 sm:p-8">
        <p className="text-center text-xs font-semibold uppercase tracking-wide text-muted">VAPT Platform</p>
        <h1 className="mt-2 text-center text-2xl font-semibold text-text">Reset password</h1>
        <p className="mt-2 text-center text-sm text-muted">Choose a new password for your account.</p>
        <form className="mt-8 space-y-4" onSubmit={onSubmit}>
          <div>
            <label htmlFor="newPassword" className="mb-1 block text-sm text-muted">New password</label>
            <input id="newPassword" name="newPassword" type="password" required value={newPassword} onChange={(e) => setNewPassword(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
          </div>
          <div>
            <label htmlFor="confirmPassword" className="mb-1 block text-sm text-muted">Confirm password</label>
            <input id="confirmPassword" name="confirmPassword" type="password" required value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
          </div>
          {message ? (<p className="text-sm text-success" role="status">{message}</p>) : null}
          {error ? (<p className="text-sm text-danger" role="alert">{error}</p>) : null}
          <button type="submit" disabled={submitting} className="w-full rounded-sm bg-primary px-3 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-60">{submitting ? "Resetting..." : "Reset password"}</button>
          <div className="text-center">
            <Link href="/login" className="text-sm text-primary hover:underline">Back to sign in</Link>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<LoadingState message="Loading security data..." />}>
      <ResetForm />
    </Suspense>
  );
}

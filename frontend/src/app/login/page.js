"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { ApiError, useAuth } from "@/lib/auth/AuthProvider";
import LoadingState from "@/components/ui/LoadingState";

function safeNextPath(value) {
  if (!value || !value.startsWith("/") || value.startsWith("//")) {
    return "/dashboard";
  }
  if (value.startsWith("/login")) {
    return "/dashboard";
  }
  return value;
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login, mfaVerify, status } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [mfaToken, setMfaToken] = useState(null);
  const [mfaCode, setMfaCode] = useState("");

  const nextPath = safeNextPath(searchParams.get("next"));

  useEffect(() => {
    if (status === "authenticated") {
      router.replace(nextPath);
    }
  }, [status, router, nextPath]);

  async function onSubmit(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const res = await login(email.trim(), password);
      if (res && res.mfa_required) {
        setMfaToken(res.mfa_token);
      } else {
        router.replace(nextPath);
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Unable to connect to the security service.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function onMfaSubmit(event) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await mfaVerify(mfaToken, mfaCode.trim());
      router.replace(nextPath);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Unable to verify code.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (status === "loading" || status === "authenticated") {
    return <LoadingState message="Loading security data..." />;
  }

  // MFA challenge view
  if (mfaToken) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-canvas px-4 py-10">
        <div className="w-full max-w-md rounded-md border border-border bg-surface p-6 sm:p-8">
          <p className="text-center text-xs font-semibold uppercase tracking-wide text-muted">VAPT Platform</p>
          <h1 className="mt-2 text-center text-2xl font-semibold text-text">Two-factor authentication</h1>
          <p className="mt-2 text-center text-sm text-muted">Enter the 6-digit code from your authenticator or a recovery code.</p>
          <form className="mt-8 space-y-4" onSubmit={onMfaSubmit}>
            <div>
              <label htmlFor="mfa-code" className="mb-1 block text-sm text-muted">Authentication code</label>
              <input id="mfa-code" name="mfa-code" type="text" inputMode="numeric" autoComplete="one-time-code" required value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} placeholder="123456 or XXXX-XXXX-XXXX" className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
            </div>
            {error ? (<p className="text-sm text-danger" role="alert">{error}</p>) : null}
            <button type="submit" disabled={submitting} className="w-full rounded-sm bg-primary px-3 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-60">{submitting ? "Verifying..." : "Verify"}</button>
            <button type="button" onClick={() => { setMfaToken(null); setMfaCode(""); setError(""); }} className="w-full text-sm text-muted underline">Back to sign in</button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4 py-10">
      <div className="w-full max-w-md rounded-md border border-border bg-surface p-6 sm:p-8">
        <p className="text-center text-xs font-semibold uppercase tracking-wide text-muted">VAPT Platform</p>
        <h1 className="mt-2 text-center text-2xl font-semibold text-text">Sign in</h1>
        <p className="mt-2 text-center text-sm text-muted">Secure your attack surface</p>
        <form className="mt-8 space-y-4" onSubmit={onSubmit}>
          <div>
            <label htmlFor="email" className="mb-1 block text-sm text-muted">Email</label>
            <input id="email" name="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
          </div>
          <div>
            <label htmlFor="password" className="mb-1 block text-sm text-muted">Password</label>
            <input id="password" name="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
          </div>
          <div className="flex justify-end">
            <Link href="/forgot-password" className="text-sm text-primary hover:underline">Forgot password?</Link>
          </div>
          {error ? (<p className="text-sm text-danger" role="alert">{error}</p>) : null}
          <button type="submit" disabled={submitting} className="w-full rounded-sm bg-primary px-3 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-60">{submitting ? "Signing in..." : "Sign In"}</button>
        </form>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<LoadingState message="Loading security data..." />}>
      <LoginForm />
    </Suspense>
  );
}

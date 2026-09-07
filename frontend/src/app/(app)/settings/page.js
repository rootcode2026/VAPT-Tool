"use client";

import { useEffect, useState } from "react";
import PageHeader from "@/components/ui/PageHeader";
import { useAuth } from "@/lib/auth/AuthProvider";
import { getMfaStatus, mfaSetup, mfaSetupVerify, mfaDisable, mfaRegenerate, changePassword, getOrgMfaPolicy, setOrgMfaPolicy } from "@/lib/api/auth";
import { restartOnboarding } from "@/lib/api/onboarding";
import { useTour } from "@/components/onboarding/TourProvider";

export default function SettingsPage() {
  const { user } = useAuth();
  const { restart } = useTour();
  const [mfaStatus, setMfaStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [setupData, setSetupData] = useState(null);
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [verifyCode, setVerifyCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState(null);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [changeCurrent, setChangeCurrent] = useState("");
  const [changeNew, setChangeNew] = useState("");
  const [changeConfirm, setChangeConfirm] = useState("");
  const [message, setMessage] = useState("");
  const [orgPolicy, setOrgPolicy] = useState(null);

  async function load() {
    try {
      const s = await getMfaStatus();
      setMfaStatus(s);
      if (user?.organization_id) {
        try {
          const p = await getOrgMfaPolicy(user.organization_id);
          setOrgPolicy(p);
        } catch {}
      }
    } catch (e) {
      setError(e.message || "Unable to load security settings.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load();
  }, [user]);

  async function onSetup() {
    setError(""); setMessage("");
    try {
      const data = await mfaSetup();
      setSetupData(data);
      // Generate QR via client-side using qrcode if available, fallback to text
      try {
        const QRCode = (await import("qrcode")).default;
        const url = await QRCode.toDataURL(data.otpauth_uri);
        setQrDataUrl(url);
      } catch {
        setQrDataUrl("");
      }
    } catch (e) {
      setError(e.message || "Unable to start MFA setup.");
    }
  }

  async function onVerify(e) {
    e.preventDefault();
    setError(""); setMessage("");
    try {
      const res = await mfaSetupVerify(verifyCode.trim());
      setRecoveryCodes(res.recovery_codes);
      setSetupData(null);
      setVerifyCode("");
      setMessage("MFA enabled.");
      load();
    } catch (err) {
      setError(err.message || "Invalid code.");
    }
  }

  async function onDisable(e) {
    e.preventDefault();
    setError(""); setMessage("");
    try {
      await mfaDisable(disablePassword, disableCode.trim());
      setMessage("MFA disabled.");
      setDisablePassword(""); setDisableCode("");
      load();
    } catch (err) {
      setError(err.message || "Unable to disable MFA.");
    }
  }

  async function onRegenerate(e) {
    e.preventDefault();
    setError(""); setMessage("");
    try {
      const res = await mfaRegenerate(disablePassword, disableCode.trim());
      setRecoveryCodes(res.recovery_codes);
      setMessage("Recovery codes regenerated.");
      load();
    } catch (err) {
      setError(err.message || "Unable to regenerate codes.");
    }
  }

  async function onChangePassword(e) {
    e.preventDefault();
    setError(""); setMessage("");
    try {
      await changePassword(changeCurrent, changeNew, changeConfirm);
      setMessage("Password changed.");
      setChangeCurrent(""); setChangeNew(""); setChangeConfirm("");
    } catch (err) {
      setError(err.message || "Unable to change password.");
    }
  }

  async function onOrgPolicyToggle() {
    if (!orgPolicy) return;
    setError(""); setMessage("");
    try {
      const res = await setOrgMfaPolicy(user.organization_id, !orgPolicy.mfa_required);
      setOrgPolicy(res);
      setMessage(res.mfa_required ? "MFA required for organization." : "MFA optional for organization.");
    } catch (err) {
      setError(err.message || "Unable to update policy.");
    }
  }

  if (loading) return <div><PageHeader title="Settings" description="Workspace identity and security." /><p className="text-sm text-muted">Loading...</p></div>;

  const mfaEnabled = mfaStatus?.mfa_enabled;
  const mfaRequired = mfaStatus?.mfa_required;

  return (
    <div>
      <PageHeader title="Settings" description="Workspace identity and security." />
      <div className="space-y-6 max-w-2xl">
        <section className="rounded-md border border-border bg-surface p-5">
          <h2 className="font-semibold text-text">Profile</h2>
          <dl className="mt-3 space-y-2 text-sm">
            <div><dt className="text-muted">Email</dt><dd className="mt-1 text-text">{user?.email || "—"}</dd></div>
            <div><dt className="text-muted">Role</dt><dd className="mt-1 text-text">{user?.role || "—"}</dd></div>
            <div><dt className="text-muted">Organization</dt><dd className="mt-1 text-text">{user?.organization_name || "—"}</dd></div>
          </dl>
        </section>

        <section className="rounded-md border border-border bg-surface p-5">
          <h2 className="font-semibold text-text">Multi-factor authentication</h2>
          <p className="mt-1 text-sm text-muted">Status: {mfaEnabled ? "Enabled ✓" : "Disabled"} {mfaRequired ? "(Required)" : "(Optional)"}</p>
          {mfaStatus?.recovery_codes_remaining != null ? (<p className="text-sm text-muted">Recovery codes remaining: {mfaStatus.recovery_codes_remaining}</p>) : null}
          {mfaRequired && !mfaEnabled ? (<p className="text-sm text-danger mt-2">MFA is required for your account. Please enable it.</p>) : null}
          {!mfaEnabled ? (
            <div className="mt-4">
              {!setupData ? (<button onClick={onSetup} className="rounded-sm bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Enable MFA</button>) : (
                <div className="space-y-4">
                  <p className="text-sm text-muted">Scan this QR code with your authenticator app, then enter the 6-digit code.</p>
                  {qrDataUrl ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img src={qrDataUrl} alt="MFA QR code" className="h-48 w-48 border border-border" />
                  ) : (<p className="text-xs break-all text-muted">{setupData.otpauth_uri}</p>)}
                  <p className="text-xs text-muted">Manual key: <span className="font-mono text-text">{setupData.secret}</span></p>
                  <form onSubmit={onVerify} className="space-y-2">
                    <label htmlFor="verify-code" className="block text-sm text-muted">Verification code</label>
                    <input id="verify-code" value={verifyCode} onChange={(e)=>setVerifyCode(e.target.value)} placeholder="123456" className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
                    <button type="submit" className="rounded-sm bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Verify and enable</button>
                    <button type="button" onClick={()=>{setSetupData(null); setQrDataUrl("");}} className="ml-2 text-sm text-muted underline">Cancel</button>
                  </form>
                </div>
              )}
            </div>
          ) : (
            <div className="mt-4 space-y-4">
              <form onSubmit={onDisable} className="space-y-2 rounded-md border border-border p-3">
                <h3 className="text-sm font-semibold text-text">Disable MFA</h3>
                <input type="password" placeholder="Current password" value={disablePassword} onChange={(e)=>setDisablePassword(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
                <input placeholder="TOTP or recovery code" value={disableCode} onChange={(e)=>setDisableCode(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
                <button type="submit" className="rounded-sm bg-danger px-4 py-2 text-sm font-semibold text-white">Disable MFA</button>
              </form>
              <form onSubmit={onRegenerate} className="space-y-2 rounded-md border border-border p-3">
                <h3 className="text-sm font-semibold text-text">Regenerate recovery codes</h3>
                <input type="password" placeholder="Current password" value={disablePassword} onChange={(e)=>setDisablePassword(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
                <input placeholder="TOTP or recovery code" value={disableCode} onChange={(e)=>setDisableCode(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
                <button type="submit" className="rounded-sm bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Regenerate codes</button>
              </form>
            </div>
          )}
          {recoveryCodes ? (
            <div className="mt-4 rounded-md border border-border bg-canvas p-4">
              <h3 className="text-sm font-semibold text-text">Recovery codes</h3>
              <p className="text-xs text-muted">Save these securely — they will not be shown again.</p>
              <ul className="mt-2 grid grid-cols-2 gap-2 font-mono text-sm text-text">
                {recoveryCodes.map((c)=>(<li key={c} className="rounded border border-border bg-surface px-2 py-1">{c}</li>))}
              </ul>
              <button onClick={()=>setRecoveryCodes(null)} className="mt-3 text-sm text-muted underline">Dismiss</button>
            </div>
          ) : null}
        </section>

        <section className="rounded-md border border-border bg-surface p-5">
          <h2 className="font-semibold text-text">Password</h2>
          <form onSubmit={onChangePassword} className="mt-3 space-y-3">
            <input type="password" placeholder="Current password" value={changeCurrent} onChange={(e)=>setChangeCurrent(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
            <input type="password" placeholder="New password" value={changeNew} onChange={(e)=>setChangeNew(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
            <input type="password" placeholder="Confirm new password" value={changeConfirm} onChange={(e)=>setChangeConfirm(e.target.value)} className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text" />
            <button type="submit" className="rounded-sm bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Change password</button>
          </form>
        </section>

        {user?.role === "super_admin" || orgPolicy ? (
          <section className="rounded-md border border-border bg-surface p-5">
            <h2 className="font-semibold text-text">Organization MFA policy</h2>
            {orgPolicy ? (
              <div className="mt-2">
                <p className="text-sm text-muted">MFA required: {orgPolicy.mfa_required ? "Yes" : "No"}</p>
                <button onClick={onOrgPolicyToggle} className="mt-2 rounded-sm border border-border px-4 py-2 text-sm">Toggle policy</button>
              </div>
            ) : (<p className="text-sm text-muted">Loading policy...</p>)}
          </section>
        ) : null}

        <section className="rounded-md border border-border bg-surface p-5" data-tour="help">
          <h2 className="font-semibold text-text">Help & Onboarding</h2>
          <p className="mt-1 text-sm text-muted">Restart the guided tour or visit the Help Center for documentation.</p>
          <div className="mt-3 flex gap-2">
            <button type="button" onClick={restart} className="rounded-sm bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">
              Restart Product Tour
            </button>
            <a href="/help" className="rounded-sm border border-border px-4 py-2 text-sm">
              Open Help Center
            </a>
          </div>
        </section>

        {message ? (<p className="text-sm text-success" role="status">{message}</p>) : null}
        {error ? (<p className="text-sm text-danger" role="alert">{error}</p>) : null}
      </div>
    </div>
  );
}

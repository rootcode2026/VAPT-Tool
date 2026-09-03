"use client";

import { useState } from "react";
import { createTarget } from "@/lib/api/targets";
import { ApiError } from "@/lib/api/client";
import {
  SCAN_TARGET_TYPES,
  validateTargetValue,
} from "@/lib/targets/contract";

export default function AddTargetForm({ projectId, onCreated, onCancel }) {
  const [targetType, setTargetType] = useState("domain");
  const [value, setValue] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const selected = SCAN_TARGET_TYPES.find((item) => item.value === targetType);

  async function onSubmit(event) {
    event.preventDefault();
    const validation = validateTargetValue(targetType, value);
    if (validation) {
      setError(validation);
      return;
    }

    setSubmitting(true);
    setError("");
    try {
      const target = await createTarget({
        project_id: projectId,
        target_type: targetType,
        value: value.trim(),
      });
      await onCreated(target);
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Unable to add the target."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="rounded-md border border-border bg-surface p-4 sm:p-5"
    >
      <fieldset className="space-y-3">
        <legend className="text-sm font-medium text-text">Target type</legend>
        {SCAN_TARGET_TYPES.map((item) => (
          <label
            key={item.value}
            className="flex cursor-pointer gap-3 rounded-sm border border-border px-3 py-2 has-[:checked]:border-primary"
          >
            <input
              type="radio"
              name="target-type"
              value={item.value}
              checked={targetType === item.value}
              onChange={() => {
                setTargetType(item.value);
                setError("");
              }}
              className="mt-1"
            />
            <span>
              <span className="block text-sm font-medium text-text">
                {item.label}
              </span>
              <span className="block text-xs text-muted">{item.description}</span>
            </span>
          </label>
        ))}
      </fieldset>

      <div className="mt-4">
        <label htmlFor="target-value" className="mb-1 block text-sm text-muted">
          {selected?.label || "Value"}
        </label>
        <input
          id="target-value"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder={
            targetType === "url"
              ? "https://example.com"
              : targetType === "ip"
                ? "203.0.113.10"
                : "example.com"
          }
          className="w-full rounded-sm border border-border bg-canvas px-3 py-2 text-sm text-text"
        />
      </div>

      {error ? (
        <p className="mt-3 text-sm text-danger" role="alert">
          {error}
        </p>
      ) : null}

      <div className="mt-4 flex justify-end gap-2">
        {onCancel ? (
          <button
            type="button"
            onClick={onCancel}
            className="rounded-sm border border-border px-3 py-1.5 text-sm text-text hover:bg-surface-hover"
          >
            Cancel
          </button>
        ) : null}
        <button
          type="submit"
          disabled={submitting}
          className="rounded-sm bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground disabled:opacity-60"
        >
          {submitting ? "Adding..." : "Add Target"}
        </button>
      </div>
    </form>
  );
}

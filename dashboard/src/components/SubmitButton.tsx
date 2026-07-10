"use client";

import { useEffect, useRef } from "react";
import { useFormStatus } from "react-dom";
import { toast } from "./Toast";

/** Submit button for server-action forms — shows a pending state and a toast on completion. */
export function SubmitButton({ children, successMessage = "Saved", className = "primary", pendingLabel }: { children: React.ReactNode; successMessage?: string; className?: string; pendingLabel?: string }) {
  const { pending } = useFormStatus();
  const wasPending = useRef(false);

  useEffect(() => {
    if (pending) wasPending.current = true;
    else if (wasPending.current) {
      wasPending.current = false;
      toast(successMessage);
    }
  }, [pending, successMessage]);

  return (
    <button type="submit" className={className} disabled={pending}>
      {pending ? pendingLabel ?? "Saving…" : children}
    </button>
  );
}

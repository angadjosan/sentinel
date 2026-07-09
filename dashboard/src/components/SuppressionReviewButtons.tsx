"use client";

import { useRouter } from "next/navigation";
import { approveSuppressionAction, rejectSuppressionAction } from "../app/team/actions";

// Approve/reject a pending suppression from the Team page. The reviewer is
// prompted for a reason (parity with the CLI's required `--reason`) rather than
// writing a hardcoded string — the API enforces a minimum-length reason.
export function SuppressionReviewButtons({ findingId }: { findingId: string }) {
  const router = useRouter();

  async function review(action: "approve" | "reject") {
    const verb = action === "approve" ? "approving" : "rejecting";
    const reason = window.prompt(`Reason for ${verb} this suppression (required):`);
    if (reason === null) return; // cancelled
    const trimmed = reason.trim();
    if (trimmed.length < 10) {
      window.alert("A reason of at least 10 characters is required.");
      return;
    }
    const form = new FormData();
    form.set("finding_id", findingId);
    form.set("reason", trimmed);
    if (action === "approve") {
      await approveSuppressionAction(form);
    } else {
      await rejectSuppressionAction(form);
    }
    router.refresh();
  }

  return (
    <div style={{ display: "flex", gap: 8 }}>
      <button
        type="button"
        className="primary"
        style={{ padding: "4px 12px", fontSize: 12 }}
        onClick={() => review("approve")}
      >
        Approve
      </button>
      <button
        type="button"
        className="danger"
        style={{ padding: "4px 12px", fontSize: 12 }}
        onClick={() => review("reject")}
      >
        Reject
      </button>
    </div>
  );
}

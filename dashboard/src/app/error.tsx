"use client";

export default function Error({
  error,
  reset,
}: {
  error: Error;
  reset: () => void;
}) {
  const isBackendDown =
    error.message.includes("fetch") ||
    error.message.includes("ECONNREFUSED") ||
    error.message.includes("network");

  return (
    <div style={{ padding: "2rem", textAlign: "center" }}>
      <h2>Something went wrong</h2>
      <p>
        {isBackendDown
          ? "Cannot reach the Sentinel backend. Make sure it is running."
          : error.message}
      </p>
      <button
        onClick={reset}
        style={{ marginTop: "1rem", padding: "0.5rem 1rem", cursor: "pointer" }}
      >
        Try again
      </button>
    </div>
  );
}

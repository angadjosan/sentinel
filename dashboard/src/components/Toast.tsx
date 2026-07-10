"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, AlertCircle, Info, X } from "lucide-react";

type ToastType = "success" | "error" | "info";
type ToastItem = { id: number; message: string; type: ToastType };

let counter = 0;

/** Fire a toast from any client component: toast("Saved"). */
export function toast(message: string, type: ToastType = "success") {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent("sentinel:toast", { detail: { message, type } }));
}

const ICON = {
  success: <CheckCircle2 size={16} />,
  error: <AlertCircle size={16} />,
  info: <Info size={16} />
};

export function Toaster() {
  const [items, setItems] = useState<ToastItem[]>([]);

  useEffect(() => {
    function onToast(event: Event) {
      const detail = (event as CustomEvent).detail as { message: string; type?: ToastType };
      const id = ++counter;
      setItems((prev) => [...prev, { id, message: detail.message, type: detail.type ?? "success" }]);
      setTimeout(() => setItems((prev) => prev.filter((item) => item.id !== id)), 3400);
    }
    window.addEventListener("sentinel:toast", onToast);
    return () => window.removeEventListener("sentinel:toast", onToast);
  }, []);

  return (
    <div className="toaster">
      {items.map((item) => (
        <div key={item.id} className={`toast ${item.type}`}>
          <span className="toast-icon">{ICON[item.type]}</span>
          <span style={{ flex: 1 }}>{item.message}</span>
          <button className="ghost icon sm" onClick={() => setItems((prev) => prev.filter((i) => i.id !== item.id))}><X size={13} /></button>
        </div>
      ))}
    </div>
  );
}

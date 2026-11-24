import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { CheckCircle2, AlertTriangle, Info, XCircle, X } from "lucide-react";

type Toast = { id: number; kind: "success" | "error" | "info" | "warn"; message: string };
type ToastApi = { push: (kind: Toast["kind"], message: string) => void };

const ToastContext = createContext<ToastApi>({ push: () => {} });

export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((kind: Toast["kind"], message: string) => {
    const id = Date.now() + Math.random();
    setToasts((list) => [...list.slice(-4), { id, kind, message }]);
    setTimeout(() => setToasts((list) => list.filter((t) => t.id !== id)), 5000);
  }, []);
  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <div className="toast-stack">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.kind}`}>
            {toast.kind === "success" ? <CheckCircle2 size={16} /> : toast.kind === "error" ? <XCircle size={16} /> : toast.kind === "warn" ? <AlertTriangle size={16} /> : <Info size={16} />}
            <span>{toast.message}</span>
            <button className="icon-btn" onClick={() => setToasts((list) => list.filter((t) => t.id !== toast.id))}>
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function Skeleton({ w, h = 14, style }: { w?: number | string; h?: number; style?: React.CSSProperties }) {
  return <span className="skeleton" style={{ display: "block", width: w ?? "100%", height: h, borderRadius: 6, ...style }} />;
}

export function PageHeaderSkeleton() {
  return (
    <div className="toolbar">
      <div style={{ display: "grid", gap: 8 }}>
        <Skeleton w={70} h={10} />
        <Skeleton w={160} h={24} />
        <Skeleton w={240} h={12} />
      </div>
    </div>
  );
}

export function MetricsSkeleton({ count = 3 }: { count?: number }) {
  return (
    <section className="grid metrics-3">
      {Array.from({ length: count }).map((_, i) => (
        <div className="panel metric" key={i} style={{ gap: 12 }}>
          <Skeleton w={110} h={12} />
          <Skeleton w={60} h={26} />
          <Skeleton w={140} h={11} />
        </div>
      ))}
    </section>
  );
}

export function RowsSkeleton({ count = 6 }: { count?: number }) {
  return (
    <section className="panel flush">
      {Array.from({ length: count }).map((_, i) => (
        <div className="sk-row" key={i}>
          <Skeleton w={9} h={9} style={{ borderRadius: 999, flexShrink: 0 }} />
          <div style={{ flex: 1, display: "grid", gap: 8 }}>
            <Skeleton w={`${45 + ((i * 7) % 35)}%`} h={14} />
            <Skeleton w={180} h={11} />
          </div>
          <Skeleton w={70} h={22} style={{ borderRadius: 999 }} />
        </div>
      ))}
    </section>
  );
}

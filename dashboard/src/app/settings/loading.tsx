import { PageHeaderSkeleton, Skeleton } from "../../components/Skeleton";

export default function Loading() {
  return (
    <>
      <PageHeaderSkeleton />
      <div className="settings-shell">
        <aside className="settings-nav" style={{ display: "grid", gap: 6 }}>
          {Array.from({ length: 8 }).map((_, i) => (<Skeleton key={i} h={20} />))}
        </aside>
        <div style={{ display: "grid", gap: 22 }}>
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i}>
              <Skeleton w={180} h={18} style={{ marginBottom: 12 }} />
              <div className="panel"><div className="panel-body" style={{ display: "grid", gap: 14 }}><Skeleton h={36} /><Skeleton h={36} /><Skeleton w={120} h={34} style={{ justifySelf: "end" }} /></div></div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

import { Skeleton } from "../../../components/Skeleton";

export default function Loading() {
  return (
    <>
      <div className="toolbar">
        <div style={{ display: "grid", gap: 8 }}>
          <Skeleton w={70} h={22} style={{ borderRadius: 999 }} />
          <Skeleton w={180} h={24} />
          <Skeleton w={280} h={11} />
        </div>
      </div>
      <section className="panel">
        <div className="statbar" style={{ gridTemplateColumns: "repeat(5, minmax(0,1fr))" }}>
          {Array.from({ length: 5 }).map((_, i) => (
            <div className="stat" key={i}><Skeleton w={80} h={12} /><Skeleton w={50} h={20} style={{ marginTop: 6 }} /></div>
          ))}
        </div>
      </section>
      <div className="panel" style={{ marginTop: 14 }}><div className="panel-body"><Skeleton h={200} /></div></div>
    </>
  );
}

import { PageHeaderSkeleton, Skeleton } from "../../components/Skeleton";

export default function Loading() {
  return (
    <>
      <PageHeaderSkeleton />
      <section className="panel" style={{ marginBottom: 14 }}>
        <div className="statbar" style={{ gridTemplateColumns: "repeat(5, minmax(0,1fr))" }}>
          {Array.from({ length: 5 }).map((_, i) => (
            <div className="stat" key={i}><Skeleton w={90} h={12} /><Skeleton w={40} h={20} style={{ marginTop: 6 }} /></div>
          ))}
        </div>
      </section>
      <div className="panel"><Skeleton h={560} style={{ borderRadius: 0 }} /></div>
    </>
  );
}

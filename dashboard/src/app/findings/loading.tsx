import { PageHeaderSkeleton, RowsSkeleton, Skeleton } from "../../components/Skeleton";

export default function Loading() {
  return (
    <>
      <PageHeaderSkeleton />
      <div className="inbox">
        <aside className="filter-rail" style={{ display: "grid", gap: 12 }}>
          {Array.from({ length: 10 }).map((_, i) => (<Skeleton key={i} h={26} />))}
        </aside>
        <RowsSkeleton count={8} />
      </div>
    </>
  );
}

import { PageHeaderSkeleton, MetricsSkeleton, RowsSkeleton } from "../components/Skeleton";

export default function Loading() {
  return (
    <>
      <PageHeaderSkeleton />
      <MetricsSkeleton />
      <div style={{ marginTop: 14 }}>
        <RowsSkeleton count={5} />
      </div>
    </>
  );
}

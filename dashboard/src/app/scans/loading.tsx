import { PageHeaderSkeleton, RowsSkeleton } from "../../components/Skeleton";

export default function Loading() {
  return (
    <>
      <PageHeaderSkeleton />
      <RowsSkeleton count={6} />
    </>
  );
}

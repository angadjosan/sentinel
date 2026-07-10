import { Skeleton } from "../../../components/Skeleton";

export default function Loading() {
  return (
    <>
      <div className="toolbar">
        <div style={{ display: "grid", gap: 8 }}>
          <Skeleton w={80} h={22} style={{ borderRadius: 999 }} />
          <Skeleton w={120} h={11} />
          <Skeleton w={360} h={24} />
        </div>
      </div>
      <Skeleton h={72} style={{ borderRadius: 10 }} />
      <div className="grid two detail-grid" style={{ marginTop: 14 }}>
        <div className="panel"><div className="panel-body" style={{ display: "grid", gap: 10 }}><Skeleton h={14} /><Skeleton h={14} /><Skeleton w="70%" h={14} /></div></div>
        <div className="panel"><div className="panel-body"><Skeleton h={120} /></div></div>
      </div>
      <div className="panel" style={{ marginTop: 14 }}><div className="panel-body"><Skeleton h={220} /></div></div>
    </>
  );
}

import { PlanReviewForm } from "../../components/PlanReviewForm";
import { listRepos, type Repo } from "../../lib/api";

export default async function PlanPage() {
  const repos = await listRepos().catch((): Repo[] => []);
  return (
    <>
      <div className="toolbar">
        <div>
          <div className="eyebrow">Shift left</div>
          <h1>Plan review</h1>
          <div className="sub">Security-review a plan against the code graph <em>before</em> any code is written — <code>sentinel plan</code>.</div>
        </div>
      </div>
      <PlanReviewForm repos={repos} />
    </>
  );
}

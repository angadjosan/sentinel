
## Evals

Goal = BLOW AS MANY EVALS OUT OF THE WATER AS POSSIBLE.

Published as: raw model vs. raw model + Sentinel.

1. Can the agent successfully load the app? (Node, Python, C/C++, Go, etc.)
2. Can the agent surface all true positive vulnerabilities in the environment?
   - Web/logic vulns: OWASP Top 10, auth bypass, injection, SSRF
   - Memory safety vulns: heap overflow, use-after-free, uninitialized read, integer overflow → corruption
   - Concurrency vulns: data races, lock-order violations
3. Can the agent correctly eliminate false positives — turning them into true negatives — via pentesting?
4. Does the sanitizer oracle fire on all confirmed memory safety findings? (Zero confirmed memory safety findings without a sanitizer stack trace is a passing grade; any confirmed finding without one is a failing grade.)
5. Coverage: what fraction of crash-triggering inputs were found by the fuzzing tier vs. required manual harness authoring?

---

## Long Vision

Sentinel becomes an open prompt: a powerful natural-language interface for querying security state across your entire codebase.

1. A set of open source evals for all cybersecurity things.
2. An RL environment for labs to learn how to use Sentinel (replace CLI + skills)

Open source RL for labs to be able to do better cybersecurity - actual substance of the sentinel model wrapper. Like actually better cybersecurity

Evals. Evals. Evals. Evals = IP = win.


theses to prove:

metrics:

impact = A/B test (raw model vs w/ Sentinel)

false positive and false negative rate
- pentest impact on this
- SCA reachability impact on this
- SAST impact on this.

benefits of source-aware pentest
- number of fuzz calls
- quality of fuzz calls
- number of graph queries + some graph traversal stat
- number of greps

benefits of reachability
- number of prunings
- number of graph queries + some graph traversal stat
- number of greps

metrics on the graph
- usefulness of graph
- number of nodes, edges, types of edges, etc. interesting things here

latency + token efficiency
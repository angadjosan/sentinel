import { test } from "node:test";
import assert from "node:assert/strict";
import { ConfigSchema } from "../src/config/sentinel.config.js";

test("apiUrl defaults to the hosted backend", () => {
  const cfg = ConfigSchema.parse({ repoName: "demo" });
  assert.equal(cfg.apiUrl, "https://sentinel-api.vercel.app");
});

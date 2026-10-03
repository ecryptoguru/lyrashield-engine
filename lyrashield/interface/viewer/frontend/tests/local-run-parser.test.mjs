import assert from "node:assert/strict";
import test from "node:test";

import { parseVulnerabilitiesJson, RunParseError } from "../src/lib/local-run-parser.ts";

test("finding parser preserves supported nested metadata after validating its shape", () => {
  const [finding] = parseVulnerabilitiesJson(
    JSON.stringify([
      {
        title: "Valid finding",
        severity: "high",
        fix_effort: "medium",
        code_locations: [
          {
            file: "src/app.ts",
            start_line: 2,
            end_line: 3,
            fix_before: "unsafe()",
            fix_after: "safe()",
          },
        ],
        cvss_breakdown: {
          attack_vector: "N",
          attack_complexity: "L",
          privileges_required: "N",
          user_interaction: "N",
          scope: "U",
          confidentiality: "H",
          integrity: "L",
          availability: "N",
        },
      },
    ])
  );

  assert.equal(finding.fix_effort, "medium");
  assert.equal(finding.code_locations?.[0]?.file, "src/app.ts");
  assert.equal(finding.cvss_breakdown?.confidentiality, "H");
});

test("finding parser rejects malformed nested values before UI rendering", () => {
  const cases = [
    JSON.stringify([[]]),
    JSON.stringify([{ title: "bad location", code_locations: [null] }]),
    JSON.stringify([{ title: "bad location", code_locations: [{ file: {}, start_line: 1 }] }]),
    JSON.stringify([{ title: "bad CVSS", cvss_breakdown: { attack_vector: {} } }]),
    JSON.stringify([{ title: "bad effort", fix_effort: "urgent" }]),
  ];

  for (const input of cases) {
    assert.throws(() => parseVulnerabilitiesJson(input), RunParseError);
  }
});

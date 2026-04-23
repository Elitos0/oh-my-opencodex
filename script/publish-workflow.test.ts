/// <reference types="bun-types" />

import { describe, expect, test } from "bun:test"
import { existsSync, readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const workflowPaths = [
  new URL("../.github/workflows/ci.yml", import.meta.url),
  new URL("../.github/workflows/publish.yml", import.meta.url),
]

describe("test workflows", () => {
  for (const workflowPath of workflowPaths) {
    const filePath = fileURLToPath(workflowPath)

    if (!existsSync(filePath)) {
      test.skip(`use pure bun test for workflows [${filePath}] (workflow not present)`, () => {})
      continue
    }

    test(`use pure bun test for workflows [${filePath}]`, () => {
      // #given
      const workflow = readFileSync(workflowPath, "utf8")

      expect(workflow).toContain("- name: Run tests")
      expect(workflow).toMatch(/run: bun (test|run script\/run-ci-tests\.ts|run test:ci)/)
    })
  }
})

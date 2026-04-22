/// <reference types="bun-types" />

type CiTestPlan = {
  isolatedTestTargets: string[]
  isolatedModuleMockFiles: string[]
  sharedTestFiles: string[]
}

const TEST_ROOTS = ["bin", "script", "src"] as const
const MODULE_MOCK_PATTERN = "mock.module("
const ALWAYS_ISOLATED_TEST_FILES = ["src/openclaw/__tests__/reply-listener-discord.test.ts"] as const

async function collectTestFiles(rootDirectory: string): Promise<string[]> {
  const testFiles: string[] = []

  for (const testRoot of TEST_ROOTS) {
    const glob = new Bun.Glob("**/*.test.ts")

    for await (const testFile of glob.scan({ cwd: `${rootDirectory}/${testRoot}` })) {
      testFiles.push(`${testRoot}/${testFile}`)
    }
  }

  return testFiles.sort((left, right) => left.localeCompare(right))
}

async function usesModuleMock(rootDirectory: string, testFile: string): Promise<boolean> {
  const testContents = await Bun.file(`${rootDirectory}/${testFile}`).text()
  return testContents.includes(MODULE_MOCK_PATTERN)
}

function toIsolatedTarget(testFile: string): string {
  return testFile
}

function isCoveredByTarget(testFile: string, isolatedTarget: string): boolean {
  return testFile === isolatedTarget || testFile.startsWith(`${isolatedTarget}/`)
}

function collapseNestedTargets(isolatedTargets: string[]): string[] {
  return isolatedTargets.filter((isolatedTarget) => {
    return !isolatedTargets.some((otherTarget) => {
      return otherTarget !== isolatedTarget && isolatedTarget.startsWith(`${otherTarget}/`)
    })
  })
}

export async function createCiTestPlan(rootDirectory: string = process.cwd()): Promise<CiTestPlan> {
  const allTestFiles = await collectTestFiles(rootDirectory)
  const isolatedModuleMockFiles: string[] = []

  for (const testFile of allTestFiles) {
    if (await usesModuleMock(rootDirectory, testFile)) {
      isolatedModuleMockFiles.push(testFile)
    }
  }

  const isolatedTestFiles = Array.from(
    new Set([...isolatedModuleMockFiles, ...ALWAYS_ISOLATED_TEST_FILES.filter((testFile) => allTestFiles.includes(testFile))]),
  )
  const isolatedTestTargets = collapseNestedTargets(
    isolatedTestFiles.map((testFile) => toIsolatedTarget(testFile)).sort((left, right) =>
      left.localeCompare(right),
    ),
  )
  const sharedTestFiles = allTestFiles.filter((testFile) => {
    return !isolatedTestTargets.some((isolatedTarget) => isCoveredByTarget(testFile, isolatedTarget))
  })

  return {
    isolatedTestTargets,
    isolatedModuleMockFiles,
    sharedTestFiles,
  }
}

async function runBunTest(testFiles: string[], label: string): Promise<number> {
  if (testFiles.length === 0) {
    return 0
  }

  console.log(`::group::${label}`)

  const command = ["bun", "test", ...testFiles]
  const spawnedProcess = Bun.spawn(command, {
    cwd: process.cwd(),
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  })
  const exitCode = await spawnedProcess.exited
  console.log("::endgroup::")

  return exitCode
}

type FailedGroup = {
  label: string
  exitCode: number
}

async function main(): Promise<void> {
  const ciTestPlan = await createCiTestPlan()

  console.log(
    `Detected ${ciTestPlan.isolatedModuleMockFiles.length} mock.module() test files, ${ciTestPlan.isolatedTestTargets.length} isolated targets, and ${ciTestPlan.sharedTestFiles.length} shared test files.`,
  )

  const failedGroups: FailedGroup[] = []

  for (const isolatedTestTarget of ciTestPlan.isolatedTestTargets) {
    const label = `Isolated ${isolatedTestTarget}`
    const exitCode = await runBunTest([isolatedTestTarget], label)
    if (exitCode !== 0) {
      failedGroups.push({ label, exitCode })
    }
  }

  const sharedLabel = "Shared Bun test suite"
  const sharedExitCode = await runBunTest(ciTestPlan.sharedTestFiles, sharedLabel)
  if (sharedExitCode !== 0) {
    failedGroups.push({ label: sharedLabel, exitCode: sharedExitCode })
  }

  if (failedGroups.length > 0) {
    console.error("")
    console.error(`${failedGroups.length} test group(s) failed:`)
    for (const group of failedGroups) {
      console.error(`  - ${group.label} (exit code ${group.exitCode})`)
    }
    process.exit(1)
  }
}

export const moduleMockPattern = MODULE_MOCK_PATTERN
export const testRoots = TEST_ROOTS

if (process.argv.includes("--print-plan")) {
  const ciTestPlan = await createCiTestPlan()
  console.log(JSON.stringify(ciTestPlan, null, 2))
} else if (import.meta.main) {
  await main()
}

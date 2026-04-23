import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync, renameSync } from "node:fs"
import { dirname, join } from "node:path"
import { randomUUID } from "node:crypto"
import yaml from "js-yaml"
import { parseFrontmatter } from "../../shared/frontmatter"
import type { RalphLoopState } from "./types"
import { DEFAULT_STATE_FILE, DEFAULT_COMPLETION_PROMISE, DEFAULT_MAX_ITERATIONS, ULTRAWORK_MAX_ITERATIONS } from "./constants"

export function getStateFilePath(directory: string, customPath?: string): string {
  return customPath
    ? join(directory, customPath)
    : join(directory, DEFAULT_STATE_FILE)
}

export function readState(directory: string, customPath?: string): RalphLoopState | null {
  const filePath = getStateFilePath(directory, customPath)

  if (!existsSync(filePath)) {
    return null
  }

  try {
    const content = readFileSync(filePath, "utf-8")
    const { data, body } = parseFrontmatter<Record<string, unknown>>(content)

    const active = data.active
    const iteration = data.iteration
    
    if (active === undefined || iteration === undefined) {
      return null
    }

    const isActive = active === true || active === "true"
    const iterationNum = typeof iteration === "number" ? iteration : Number(iteration)
    
    if (isNaN(iterationNum)) {
      return null
    }

    const stripQuotes = (val: unknown): string => {
      const str = String(val ?? "")
      return str.replace(/^["']|["']$/g, "")
    }

    const ultrawork = data.ultrawork === true || data.ultrawork === "true" ? true : undefined
    const maxIterations =
      data.max_iterations === undefined || data.max_iterations === ""
        ? ultrawork
          ? ULTRAWORK_MAX_ITERATIONS
          : DEFAULT_MAX_ITERATIONS
        : Number(data.max_iterations) || DEFAULT_MAX_ITERATIONS

    return {
      active: isActive,
      iteration: iterationNum,
      max_iterations: maxIterations,
      message_count_at_start:
        typeof data.message_count_at_start === "number"
          ? data.message_count_at_start
          : typeof data.message_count_at_start === "string" && data.message_count_at_start.trim() !== ""
            ? Number(data.message_count_at_start)
            : undefined,
      completion_promise: stripQuotes(data.completion_promise) || DEFAULT_COMPLETION_PROMISE,
      initial_completion_promise: data.initial_completion_promise
        ? stripQuotes(data.initial_completion_promise)
        : undefined,
      verification_attempt_id: data.verification_attempt_id
        ? stripQuotes(data.verification_attempt_id)
        : undefined,
      verification_session_id: data.verification_session_id
        ? stripQuotes(data.verification_session_id)
        : undefined,
      started_at: stripQuotes(data.started_at) || new Date().toISOString(),
      prompt: body.trim(),
      session_id: data.session_id ? stripQuotes(data.session_id) : undefined,
      ultrawork,
      verification_pending:
        data.verification_pending === true || data.verification_pending === "true"
          ? true
          : undefined,
      strategy: data.strategy === "reset" || data.strategy === "continue" ? data.strategy : undefined,
    }
  } catch {
    return null
  }
}

export function writeState(
  directory: string,
  state: RalphLoopState,
  customPath?: string
): boolean {
  const filePath = getStateFilePath(directory, customPath)

  try {
    const dir = dirname(filePath)
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })
    }

    const frontmatter: Record<string, unknown> = {
      active: state.active,
      iteration: state.iteration,
      completion_promise: state.completion_promise,
      started_at: state.started_at,
    }
    if (typeof state.max_iterations === "number") {
      frontmatter.max_iterations = state.max_iterations
    }
    if (state.initial_completion_promise) {
      frontmatter.initial_completion_promise = state.initial_completion_promise
    }
    if (state.verification_attempt_id) {
      frontmatter.verification_attempt_id = state.verification_attempt_id
    }
    if (state.verification_session_id) {
      frontmatter.verification_session_id = state.verification_session_id
    }
    if (state.session_id) {
      frontmatter.session_id = state.session_id
    }
    if (state.ultrawork !== undefined) {
      frontmatter.ultrawork = state.ultrawork
    }
    if (state.verification_pending !== undefined) {
      frontmatter.verification_pending = state.verification_pending
    }
    if (state.strategy) {
      frontmatter.strategy = state.strategy
    }
    if (typeof state.message_count_at_start === "number") {
      frontmatter.message_count_at_start = state.message_count_at_start
    }

    // js-yaml with JSON_SCHEMA escapes special chars, handles multiline strings,
    // and prevents code execution via custom tags.
    const yamlBody = yaml.dump(frontmatter, {
      schema: yaml.JSON_SCHEMA,
      lineWidth: -1,
      noRefs: true,
      sortKeys: false,
    })
    const content = `---\n${yamlBody}---\n${state.prompt}\n`

    const tempPath = `${filePath}.${randomUUID()}.tmp`
    try {
      writeFileSync(tempPath, content, "utf-8")
      renameSync(tempPath, filePath)
    } catch (err) {
      try {
        if (existsSync(tempPath)) unlinkSync(tempPath)
      } catch {
        // best effort cleanup
      }
      throw err
    }
    return true
  } catch {
    return false
  }
}

export function clearState(directory: string, customPath?: string): boolean {
  const filePath = getStateFilePath(directory, customPath)

  try {
    if (existsSync(filePath)) {
      unlinkSync(filePath)
    }
    return true
  } catch {
    return false
  }
}

export function incrementIteration(
  directory: string,
  customPath?: string
): RalphLoopState | null {
  const state = readState(directory, customPath)
  if (!state) return null

  state.iteration += 1
  if (writeState(directory, state, customPath)) {
    return state
  }
  return null
}

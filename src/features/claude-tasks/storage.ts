import { join, dirname, basename, isAbsolute } from "path"
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync, readdirSync } from "fs"
import { randomUUID } from "crypto"
import { getOpenCodeConfigDir } from "../../shared/opencode-config-dir"
import type { z } from "zod"
import type { OhMyOpenCodeConfig } from "../../config/schema"

export function getTaskDir(config: Partial<OhMyOpenCodeConfig> = {}): string {
  const tasksConfig = config.sisyphus?.tasks
  const storagePath = tasksConfig?.storage_path

  if (storagePath) {
    return isAbsolute(storagePath) ? storagePath : join(process.cwd(), storagePath)
  }

  const configDir = getOpenCodeConfigDir({ binary: "opencode" })
  const listId = resolveTaskListId(config)
  return join(configDir, "tasks", listId)
}

export function sanitizePathSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9_-]/g, "-") || "default"
}

export function resolveTaskListId(config: Partial<OhMyOpenCodeConfig> = {}): string {
  const envId = process.env.ULTRAWORK_TASK_LIST_ID?.trim()
  if (envId) return sanitizePathSegment(envId)

  const claudeEnvId = process.env.CLAUDE_CODE_TASK_LIST_ID?.trim()
  if (claudeEnvId) return sanitizePathSegment(claudeEnvId)

  const configId = config.sisyphus?.tasks?.task_list_id?.trim()
  if (configId) return sanitizePathSegment(configId)

  return sanitizePathSegment(basename(process.cwd()))
}

export function ensureDir(dirPath: string): void {
  if (!existsSync(dirPath)) {
    mkdirSync(dirPath, { recursive: true })
  }
}

export function readJsonSafe<T>(filePath: string, schema: z.ZodType<T>): T | null {
  try {
    if (!existsSync(filePath)) {
      return null
    }

    const content = readFileSync(filePath, "utf-8")
    const parsed = JSON.parse(content)
    const result = schema.safeParse(parsed)

    if (!result.success) {
      return null
    }

    return result.data
  } catch {
    return null
  }
}

export function writeJsonAtomic(filePath: string, data: unknown): void {
  const dir = dirname(filePath)
  ensureDir(dir)

  const tempPath = `${filePath}.tmp.${Date.now()}.${randomUUID()}`

  try {
    writeFileSync(tempPath, JSON.stringify(data, null, 2), "utf-8")
    renameSync(tempPath, filePath)
  } catch (error) {
    try {
      if (existsSync(tempPath)) {
        unlinkSync(tempPath)
      }
    } catch {
      // Ignore cleanup errors
    }
    throw error
  }
}

const STALE_LOCK_THRESHOLD_MS = 30000

export function generateTaskId(): string {
  return `T-${randomUUID()}`
}

export function listTaskFiles(config: Partial<OhMyOpenCodeConfig> = {}): string[] {
  const dir = getTaskDir(config)
  if (!existsSync(dir)) return []
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json') && f.startsWith('T-'))
    .map((f) => f.replace('.json', ''))
}

export function acquireLock(dirPath: string): { acquired: boolean; release: () => void } {
  const lockPath = join(dirPath, ".lock")
  const lockId = randomUUID()

  const createLock = (timestamp: number) => {
    writeFileSync(lockPath, JSON.stringify({ id: lockId, timestamp }), {
      encoding: "utf-8",
      flag: "wx",
    })
  }

  const readStaleLockSnapshot = (): { raw: string } | null => {
    try {
      const raw = readFileSync(lockPath, "utf-8")
      const lockData = JSON.parse(raw)
      const lockAge = Date.now() - lockData.timestamp
      if (lockAge > STALE_LOCK_THRESHOLD_MS) {
        return { raw }
      }
      return null
    } catch {
      // Missing or unparseable lock: treat as removable (caller must tolerate races).
      return { raw: "" }
    }
  }

  const removeLockIfUnchanged = (snapshot: { raw: string }): boolean => {
    try {
      if (!existsSync(lockPath)) return false
      const current = readFileSync(lockPath, "utf-8")
      if (current !== snapshot.raw) return false
      unlinkSync(lockPath)
      return true
    } catch {
      return false
    }
  }

  const tryAcquire = () => {
    const now = Date.now()
    try {
      createLock(now)
      return true
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "EEXIST") {
        return false
      }
      throw error
    }
  }

  ensureDir(dirPath)

  let acquired = tryAcquire()
  if (!acquired) {
    const snapshot = readStaleLockSnapshot()
    if (snapshot && removeLockIfUnchanged(snapshot)) {
      acquired = tryAcquire()
    }
  }

  if (!acquired) {
    return {
      acquired: false,
      release: () => {
        // No-op release for failed acquisition
      },
    }
  }

  return {
    acquired: true,
    release: () => {
      try {
        if (!existsSync(lockPath)) return
        const lockContent = readFileSync(lockPath, "utf-8")
        const lockData = JSON.parse(lockContent)
        if (lockData.id !== lockId) return
        unlinkSync(lockPath)
      } catch {
        // Ignore cleanup errors
      }
    },
  }
}

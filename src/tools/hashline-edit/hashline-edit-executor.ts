import type { ToolContext } from "@opencode-ai/plugin/tool"
import { isAbsolute, resolve } from "node:path"
import { publishToolMetadata } from "../../features/tool-metadata-store"
import { isWithinProject } from "../../shared/contains-path"
import { applyHashlineEditsWithReport } from "./edit-operations"
import { countLineDiffs, generateUnifiedDiff } from "./diff-utils"
import { canonicalizeFileText, restoreFileText } from "./file-text-canonicalization"
import { normalizeHashlineEdits, type RawHashlineEdit } from "./normalize-edits"
import type { HashlineEdit } from "./types"
import { HashlineMismatchError } from "./validation"
import { runFormattersForFile, type FormatterClient } from "./formatter-trigger"
import type { PluginContext } from "../../plugin/types"

// Resolve a user-supplied path against the project root and verify the result
// is still inside the project (after resolving symlinks via isWithinProject).
// Returns the absolute canonical path on success, or a descriptive error string.
function resolveProjectPath(
  rawPath: string,
  projectRoot: string,
  field: "filePath" | "rename",
): { ok: true; resolved: string } | { ok: false; error: string } {
  if (typeof rawPath !== "string" || rawPath.length === 0) {
    return { ok: false, error: `Error: ${field} must be a non-empty string` }
  }
  if (!projectRoot) {
    return { ok: false, error: `Error: project directory is not set; cannot validate ${field}` }
  }

  const absolute = isAbsolute(rawPath) ? rawPath : resolve(projectRoot, rawPath)
  if (!isWithinProject(absolute, projectRoot)) {
    return {
      ok: false,
      error: `Error: ${field} escapes project root (${projectRoot}); refusing to operate on ${rawPath}`,
    }
  }
  return { ok: true, resolved: absolute }
}

interface HashlineEditArgs {
  filePath: string
  edits: RawHashlineEdit[]
  delete?: boolean
  rename?: string
}

type ToolContextWithCallID = ToolContext & {
  callID?: string
  callId?: string
  call_id?: string
}

type ToolContextWithMetadata = ToolContextWithCallID & {
  metadata?: (value: unknown) => void
}

function canCreateFromMissingFile(edits: HashlineEdit[]): boolean {
  if (edits.length === 0) return false
  return edits.every((edit) => (edit.op === "append" || edit.op === "prepend") && !edit.pos)
}

function buildSuccessMeta(
  effectivePath: string,
  beforeContent: string,
  afterContent: string,
  noopEdits: number,
  deduplicatedEdits: number
) {
  const unifiedDiff = generateUnifiedDiff(beforeContent, afterContent, effectivePath)
  const { additions, deletions } = countLineDiffs(beforeContent, afterContent)
  const beforeLines = beforeContent.split("\n")
  const afterLines = afterContent.split("\n")
  const maxLength = Math.max(beforeLines.length, afterLines.length)
  let firstChangedLine: number | undefined

  for (let index = 0; index < maxLength; index += 1) {
    if ((beforeLines[index] ?? "") !== (afterLines[index] ?? "")) {
      firstChangedLine = index + 1
      break
    }
  }

  return {
    title: effectivePath,
    metadata: {
      filePath: effectivePath,
      path: effectivePath,
      file: effectivePath,
      diff: unifiedDiff,
      noopEdits,
      deduplicatedEdits,
      firstChangedLine,
      filediff: {
        file: effectivePath,
        path: effectivePath,
        filePath: effectivePath,
        before: beforeContent,
        after: afterContent,
        additions,
        deletions,
      },
    },
  }
}

export async function executeHashlineEditTool(args: HashlineEditArgs, context: ToolContext, pluginCtx?: PluginContext): Promise<string> {
  try {
    const metadataContext = context as ToolContextWithMetadata
    const { delete: deleteMode } = args

    if (deleteMode && args.rename) {
      return "Error: delete and rename cannot be used together"
    }
    if (deleteMode && args.edits.length > 0) {
      return "Error: delete mode requires edits to be an empty array"
    }

    if (!deleteMode && (!args.edits || !Array.isArray(args.edits) || args.edits.length === 0)) {
      return "Error: edits parameter must be a non-empty array"
    }

    // Guard against path traversal and symlink escape. Both filePath and rename
    // must resolve inside context.directory; isWithinProject follows symlinks
    // via realpath so an attacker-controlled symlink pointing at ~/.ssh or /etc
    // cannot be used to smuggle writes outside the project.
    const projectRoot = context.directory ?? ""
    const filePathCheck = resolveProjectPath(args.filePath, projectRoot, "filePath")
    if (!filePathCheck.ok) return filePathCheck.error
    const filePath = filePathCheck.resolved

    let rename: string | undefined
    if (args.rename) {
      const renameCheck = resolveProjectPath(args.rename, projectRoot, "rename")
      if (!renameCheck.ok) return renameCheck.error
      rename = renameCheck.resolved
    }

    const edits = deleteMode ? [] : normalizeHashlineEdits(args.edits)

    const file = Bun.file(filePath)
    const exists = await file.exists()
    if (!exists && !deleteMode && !canCreateFromMissingFile(edits)) {
      return `Error: File not found: ${filePath}`
    }

    if (deleteMode) {
      if (!exists) return `Error: File not found: ${filePath}`
      await Bun.file(filePath).delete()
      return `Successfully deleted ${filePath}`
    }

    const rawOldContent = exists ? Buffer.from(await file.arrayBuffer()).toString("utf8") : ""
    const oldEnvelope = canonicalizeFileText(rawOldContent)

    const applyResult = applyHashlineEditsWithReport(oldEnvelope.content, edits)
    const canonicalNewContent = applyResult.content

    if (canonicalNewContent === oldEnvelope.content && !rename) {
      let diagnostic = `No changes made to ${filePath}. The edits produced identical content.`
      if (applyResult.noopEdits > 0) {
        diagnostic += ` No-op edits: ${applyResult.noopEdits}. Re-read the file and provide content that differs from current lines.`
      }
      return `Error: ${diagnostic}`
    }

    const writeContent = restoreFileText(canonicalNewContent, oldEnvelope)

    await Bun.write(filePath, writeContent)

    if (pluginCtx?.client) {
      await runFormattersForFile(pluginCtx.client as FormatterClient, context.directory, filePath)
      const formattedContent = Buffer.from(await Bun.file(filePath).arrayBuffer()).toString("utf8")
      if (formattedContent !== writeContent) {
        const formattedEnvelope = canonicalizeFileText(formattedContent)
        const renameTarget = rename && rename !== filePath ? rename : null
        const effectivePath = renameTarget ?? filePath
        const formattedMeta = buildSuccessMeta(
          effectivePath,
          oldEnvelope.content,
          formattedEnvelope.content,
          applyResult.noopEdits,
          applyResult.deduplicatedEdits
        )
        if (renameTarget) {
          await Bun.write(renameTarget, formattedContent)
          await Bun.file(filePath).delete()
        }
        await publishToolMetadata(metadataContext, formattedMeta)
        return renameTarget ? `Moved ${filePath} to ${renameTarget}` : `Updated ${filePath}`
      }
    }

    if (rename && rename !== filePath) {
      await Bun.write(rename, writeContent)
      await Bun.file(filePath).delete()
    }

    const effectivePath = rename && rename !== filePath ? rename : filePath
    const meta = buildSuccessMeta(
      effectivePath,
      oldEnvelope.content,
      canonicalNewContent,
      applyResult.noopEdits,
      applyResult.deduplicatedEdits
    )

    await publishToolMetadata(metadataContext, meta)

    if (rename && rename !== filePath) {
      return `Moved ${filePath} to ${rename}`
    }

    return `Updated ${effectivePath}`
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    if (error instanceof HashlineMismatchError) {
      return `Error: hash mismatch - ${message}\nTip: reuse LINE#ID entries from the latest read/edit output, or batch related edits in one call.`
    }
    return `Error: ${message}`
  }
}

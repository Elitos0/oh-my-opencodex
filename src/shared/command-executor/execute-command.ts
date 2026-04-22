import { exec } from "node:child_process"
import { promisify } from "node:util"

const execAsync = promisify(exec)

type ExecError = { stdout?: Buffer; stderr?: Buffer; message?: string }

const DEFAULT_TIMEOUT_MS = 30_000
const DEFAULT_MAX_BUFFER_BYTES = 10 * 1024 * 1024

export interface ExecuteCommandOptions {
	/** Timeout in milliseconds. Process is killed after this. Default: 30000 */
	timeoutMs?: number
	/** Max stdout/stderr buffer size in bytes. Default: 10MB */
	maxBufferBytes?: number
	/** Working directory for the command. */
	cwd?: string
}

export async function executeCommand(
	command: string,
	options: ExecuteCommandOptions = {},
): Promise<string> {
	const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
	const maxBuffer = options.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES

	try {
		const { stdout, stderr } = await execAsync(command, {
			timeout,
			maxBuffer,
			cwd: options.cwd,
		})

		const out = stdout?.toString().trim() ?? ""
		const err = stderr?.toString().trim() ?? ""

		if (err) {
			return out ? `${out}\n[stderr: ${err}]` : `[stderr: ${err}]`
		}

		return out
	} catch (error: unknown) {
		const e = error as ExecError
		const stdout = e?.stdout?.toString().trim() ?? ""
		const stderr = e?.stderr?.toString().trim() ?? ""
		const errorMessage = stderr || e?.message || String(error)

		return stdout ? `${stdout}\n[stderr: ${errorMessage}]` : `[stderr: ${errorMessage}]`
	}
}

import { spawn } from 'node:child_process'

/** Returns true if `cmd` exists on PATH. Portable POSIX check. */
export async function which(cmd: string): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn('which', [cmd], { stdio: 'ignore' })
    child.once('exit', (code) => resolve(code === 0))
    child.once('error', () => resolve(false))
  })
}

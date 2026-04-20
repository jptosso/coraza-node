import { handlers } from '@coraza/example-shared'

export async function GET(): Promise<Response> {
  return new Response(handlers.healthz().body as string, {
    headers: { 'content-type': 'text/plain' },
  })
}

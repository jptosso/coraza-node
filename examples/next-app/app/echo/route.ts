import { NextResponse } from 'next/server'
import { handlers } from '@coraza/example-shared'

export async function POST(req: Request): Promise<Response> {
  const body = await req.json().catch(() => ({}))
  return NextResponse.json(handlers.echo(body).body)
}

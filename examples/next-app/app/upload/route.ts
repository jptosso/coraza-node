import { NextResponse } from 'next/server'
import { handlers } from '@coraza/example-shared'

export async function POST(req: Request): Promise<Response> {
  const buf = Buffer.from(await req.arrayBuffer())
  return NextResponse.json(handlers.upload(buf.length).body)
}

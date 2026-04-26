import { NextResponse } from 'next/server'

export async function POST(req: Request): Promise<Response> {
  const body = await req.json().catch(() => ({}))
  return NextResponse.json(body ?? {})
}

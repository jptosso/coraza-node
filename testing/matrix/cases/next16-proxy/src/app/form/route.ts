import { NextResponse } from 'next/server'

export async function POST(req: Request): Promise<Response> {
  const form = await req.formData().catch(() => new FormData())
  const received: Record<string, string> = {}
  for (const [k, v] of form.entries()) {
    if (typeof v === 'string') received[k] = v
  }
  return NextResponse.json({ received })
}

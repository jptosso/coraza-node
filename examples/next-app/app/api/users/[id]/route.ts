import { NextResponse } from 'next/server'
import { handlers } from '@coraza/example-shared'

export async function GET(
  _req: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const { id } = await context.params
  return NextResponse.json(handlers.user(id).body)
}

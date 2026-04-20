import { NextResponse, type NextRequest } from 'next/server'
import { handlers } from '@coraza/example-shared'

export async function GET(req: NextRequest): Promise<Response> {
  const q = req.nextUrl.searchParams.get('q') ?? undefined
  return NextResponse.json(handlers.search(q).body)
}

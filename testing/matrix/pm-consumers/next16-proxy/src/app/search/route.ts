import { NextResponse, type NextRequest } from 'next/server'

export async function GET(req: NextRequest): Promise<Response> {
  const q = req.nextUrl.searchParams.get('q') ?? ''
  return NextResponse.json({ q, len: q.length })
}

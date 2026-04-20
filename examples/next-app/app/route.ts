import { NextResponse } from 'next/server'
import { handlers } from '@coraza/example-shared'

export async function GET(): Promise<Response> {
  return NextResponse.json(handlers.root('next').body)
}

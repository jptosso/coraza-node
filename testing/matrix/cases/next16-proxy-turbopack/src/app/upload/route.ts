import { NextResponse } from 'next/server'

export async function POST(req: Request): Promise<Response> {
  const form = await req.formData().catch(() => null)
  if (!form) {
    return NextResponse.json({ error: 'expected multipart/form-data' }, { status: 400 })
  }
  const fields: string[] = []
  const files: { name: string; bytes: number; field: string }[] = []
  for (const [name, value] of form.entries()) {
    if (typeof value === 'string') {
      fields.push(name)
    } else {
      const buf = await value.arrayBuffer()
      files.push({ name: value.name, bytes: buf.byteLength, field: name })
    }
  }
  return NextResponse.json({ fields, files })
}

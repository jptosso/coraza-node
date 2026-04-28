import 'reflect-metadata'
import { Readable } from 'node:stream'
import express from 'express'
import multer from 'multer'
import { NestFactory } from '@nestjs/core'
import {
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  Module,
  Post,
  Query,
  Req,
} from '@nestjs/common'
import { NestExpressApplication } from '@nestjs/platform-express'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { CorazaModule } from '@coraza/nestjs'

const port = Number(process.env.PORT ?? 3000)
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)
const mode = (process.env.MODE ?? 'block') as 'detect' | 'block'
// Same three-rule disable as examples/express-app — see that file for
// the full justification. Without these the inbound anomaly score
// crosses 5 on every benign body-bearing POST at PL1.
const crsTuning = [
  'SecRuleRemoveById 920420',
  'SecRuleRemoveById 920350',
  'SecRuleRemoveById 922110',
].join('\n')
const rules = recommended({ extra: crsTuning })
const waf = usePool
  ? await createWAFPool({ rules, mode, size: poolSize })
  : await createWAF({ rules, mode })

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } })

@Controller()
class AppController {
  @Get('/')
  root(): unknown {
    return { ok: true }
  }

  @Get('/healthz')
  @Header('content-type', 'text/plain')
  healthz(): string {
    return 'ok'
  }

  @Get('/search')
  search(@Query('q') q?: string): unknown {
    const value = q ?? ''
    return { q: value, len: value.length }
  }

  @Post('/echo')
  @HttpCode(200)
  echo(@Body() body: unknown): unknown {
    return body ?? {}
  }

  @Post('/form')
  @HttpCode(200)
  form(@Body() body: unknown): unknown {
    return { received: body }
  }

  // Re-parse the buffered multipart body with multer through a synthetic
  // stream — the global express.raw parser leaves req.body as the raw
  // bytes so the WAF guard can inspect it.
  @Post('/upload')
  @HttpCode(200)
  async uploadRoute(@Req() req: express.Request): Promise<unknown> {
    if (!req.is('multipart/form-data') || !Buffer.isBuffer(req.body)) {
      return { error: 'expected multipart/form-data' }
    }
    const synthetic = Readable.from([req.body as Buffer]) as unknown as express.Request
    Object.assign(synthetic, {
      headers: req.headers,
      url: req.url,
      method: req.method,
      socket: req.socket,
    })
    delete (req as { body?: unknown }).body
    return await new Promise((resolve, reject) => {
      upload.any()(synthetic as express.Request, {} as express.Response, (err?: unknown) => {
        if (err) return reject(err)
        const sBody = (synthetic as unknown as { body?: Record<string, unknown> }).body ?? {}
        const sFiles = (synthetic as unknown as { files?: Express.Multer.File[] }).files ?? []
        resolve({
          fields: Object.keys(sBody),
          files: sFiles.map((f) => ({
            name: f.originalname,
            bytes: f.size,
            field: f.fieldname,
          })),
        })
      })
    })
  }
}

@Module({
  imports: [CorazaModule.forRoot({ waf })],
  controllers: [AppController],
})
class AppModule {}

const app = await NestFactory.create<NestExpressApplication>(AppModule, {
  logger: ['error', 'warn'],
  rawBody: true,
})
// Body parsers must be mounted on the underlying Express instance before
// the CorazaGuard runs so req.body holds the parsed/raw bytes the WAF
// inspects. NestJS's default JSON parser is fine; we add urlencoded and
// a raw parser for multipart so the WAF sees the literal multipart bytes.
app.use(express.json({ limit: '1mb' }))
app.use(express.urlencoded({ extended: true, limit: '1mb' }))
app.use(express.raw({ type: 'multipart/form-data', limit: '5mb' }))

await app.listen(port)
process.stdout.write(`matrix-nestjs11 listening on :${port}\n`)
process.on('SIGTERM', async () => {
  await app.close()
  process.exit(0)
})

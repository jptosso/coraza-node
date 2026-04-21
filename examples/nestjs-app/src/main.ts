import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import {
  All,
  Body,
  Controller,
  Get,
  Header,
  Module,
  Param,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common'
import { recommended } from '@coraza/coreruleset'
import { CorazaModule } from '@coraza/nestjs'
import { ftwEcho, ftwModeEnabled, handlers } from '@coraza/example-shared'

type RawReq = {
  body?: Buffer | unknown
  rawBody?: Buffer
  method?: string
  originalUrl?: string
  headers?: Record<string, string | string[] | undefined>
}

const ftw = ftwModeEnabled()
const port = Number(process.env.PORT ?? 3004)
const mode = ftw ? 'block' : ((process.env.MODE ?? 'block') as 'detect' | 'block')
const wafDisabled = process.env.WAF === 'off'

@Controller()
class AppController {
  @Get('/')
  root(): unknown {
    return handlers.root('nestjs').body
  }

  @Get('/healthz')
  @Header('content-type', 'text/plain')
  health(): string {
    return handlers.healthz().body as string
  }

  @Get('/search')
  search(@Query('q') q?: string): unknown {
    return handlers.search(q).body
  }

  @Post('/echo')
  echo(@Body() body: unknown): unknown {
    return handlers.echo(body).body
  }

  @Post('/upload')
  upload(@Body() body: unknown, @Req() req: RawReq): unknown {
    const buf =
      (req.rawBody as Buffer | undefined) ?? (Buffer.isBuffer(body) ? body : null)
    const len = buf ? buf.length : JSON.stringify(body ?? '').length
    return handlers.upload(len).body
  }

  @Get('/img/logo.png')
  @Header('content-type', 'image/png')
  image(@Res() res: { end: (b: Buffer) => void }): void {
    res.end(handlers.image().body as Buffer)
  }

  @Get('/api/users/:id')
  user(@Param('id') id: string): unknown {
    return handlers.user(id).body
  }
}

// In FTW mode we replace the routed controller with a catch-all that
// echoes the request back. The go-ftw corpus targets URLs the demo
// controller doesn't define, so a single named-wildcard route keeps
// every test case on the same handler. (Nest 11 runs on Express 5 /
// path-to-regexp v8, which rejects a bare `*` — named wildcard is
// required.)
@Controller()
class FtwController {
  @All('{*any}')
  echo(@Req() req: RawReq): unknown {
    const headers: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers ?? {})) {
      if (typeof v === 'string') headers[k] = v
      else if (Array.isArray(v)) headers[k] = v.join(',')
    }
    const raw = (req.rawBody as Buffer | undefined) ?? req.body
    const body = Buffer.isBuffer(raw)
      ? raw.toString('utf8')
      : typeof raw === 'string'
        ? raw
        : JSON.stringify(raw ?? '')
    return ftwEcho({
      method: req.method ?? 'GET',
      url: req.originalUrl ?? '/',
      headers,
      body,
    }).body
  }
}

const rules = recommended(ftw ? { paranoia: 2 } : {})

@Module({
  imports: wafDisabled
    ? []
    : [CorazaModule.forRoot({ rules, mode, inspectResponse: ftw })],
  controllers: [ftw ? FtwController : AppController],
})
class AppModule {}

const app = await NestFactory.create(AppModule, {
  logger: ['error', 'warn'],
  rawBody: true,
})
await app.listen(port)
console.log(
  `nestjs listening on :${port} (mode=${mode}, waf=${wafDisabled ? 'off' : 'on'}${ftw ? ', FTW=1 paranoia=2' : ''})`,
)

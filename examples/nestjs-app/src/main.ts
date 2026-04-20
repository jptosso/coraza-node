import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import {
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
import { handlers } from '@coraza/example-shared'

type RawReq = { body?: Buffer; rawBody?: Buffer }

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
    const buf = (req.rawBody as Buffer | undefined) ?? (Buffer.isBuffer(body) ? body : null)
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

const port = Number(process.env.PORT ?? 3004)
const mode = (process.env.MODE ?? 'block') as 'detect' | 'block'
const wafDisabled = process.env.WAF === 'off'

@Module({
  imports: wafDisabled ? [] : [CorazaModule.forRoot({ rules: recommended(), mode })],
  controllers: [AppController],
})
class AppModule {}

const app = await NestFactory.create(AppModule, { logger: ['error', 'warn'], rawBody: true })
await app.listen(port)
console.log(`nestjs listening on :${port} (mode=${mode}, waf=${wafDisabled ? 'off' : 'on'})`)

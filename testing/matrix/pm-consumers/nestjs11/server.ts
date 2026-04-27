// pm-consumer / nestjs11 — bare consumer, installed from tarballs by the
// target package manager. Uses TypeScript decorators (NestJS contract);
// tsx transpiles at runtime.
import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import {
  Body,
  Controller,
  Get,
  Header,
  Module,
  Post,
  Query,
} from '@nestjs/common'
import { createWAF, createWAFPool } from '@coraza/core'
import { recommended } from '@coraza/coreruleset'
import { CorazaModule } from '@coraza/nestjs'

const port = Number(process.env.PORT ?? 3000)
const usePool = process.env.POOL === '1'
const poolSize = Number(process.env.POOL_SIZE ?? 2)
const mode = (process.env.MODE ?? 'block') as 'detect' | 'block'
const rules = recommended()
const waf = usePool
  ? await createWAFPool({ rules, mode, size: poolSize })
  : await createWAF({ rules, mode })

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
  echo(@Body() body: unknown): unknown {
    return body ?? {}
  }
}

@Module({
  imports: [CorazaModule.forRoot({ waf })],
  controllers: [AppController],
})
class AppModule {}

const app = await NestFactory.create(AppModule, {
  logger: ['error', 'warn'],
  rawBody: true,
})
await app.listen(port)
process.stdout.write(`pm-consumer-nestjs11 listening on :${port}\n`)
process.on('SIGTERM', async () => {
  await app.close()
  process.exit(0)
})

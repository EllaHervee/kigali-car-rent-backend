import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bodyParser: false });
  app.getHttpAdapter().getInstance().set("trust proxy", 1);
  app.enableShutdownHooks();
  await app.listen(Number(process.env.PORT) || 3001, "0.0.0.0");
}

void bootstrap();

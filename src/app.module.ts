import { Module } from "@nestjs/common";
import { LegacyApiController } from "./legacy-api.controller";

@Module({
  controllers: [LegacyApiController],
})
export class AppModule {}

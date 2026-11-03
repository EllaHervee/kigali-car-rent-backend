import { All, Controller, Req, Res } from "@nestjs/common";
import type { Request, Response } from "express";
import { createRequire } from "node:module";
import { resolve } from "node:path";

const requireFromApp = createRequire(__filename);
const { handleVercelRequest } = requireFromApp(
  resolve(__dirname, "../src/legacy-server.js"),
) as {
  handleVercelRequest: (request: Request, response: Response) => Promise<void>;
};

@Controller()
export class LegacyApiController {
  @All("{*path}")
  handle(@Req() request: Request, @Res() response: Response) {
    return handleVercelRequest(request, response);
  }
}

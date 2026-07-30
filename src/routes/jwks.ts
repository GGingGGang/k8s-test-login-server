import type { FastifyInstance } from "fastify";

import type { SigningKey } from "../keys.js";

export interface JwksRouteOptions {
  signingKey: SigningKey;
  // secondaryKey publishes a second public key alongside the active signing
  // key, without ever being used to sign (../PLAN.md §6 rotation runbook).
  // The same slot serves both halves of a rotation: pre-cutover it holds the
  // *next* key (published ahead of time so core's JWKS cache already knows
  // its kid before signing switches over); post-cutover it holds the
  // *retiring* key (kept until tokens it signed have all expired). Which
  // phase it's in is an operational fact (which PEM was put in
  // JWT_SECONDARY_KEY_PEM), not something this route needs to know.
  secondaryKey?: SigningKey;
}

export async function jwksRoutes(app: FastifyInstance, opts: JwksRouteOptions): Promise<void> {
  const { signingKey, secondaryKey } = opts;

  app.get(
    "/.well-known/jwks.json",
    {
      schema: {
        tags: ["auth"],
        summary: "JWKS public key set",
        response: {
          200: {
            type: "object",
            properties: {
              keys: { type: "array", items: { type: "object", additionalProperties: true } },
            },
            required: ["keys"],
          },
        },
      },
    },
    async (_req, reply) => {
      reply.header("Cache-Control", "max-age=3600");
      const keys = secondaryKey ? [signingKey.publicJwk, secondaryKey.publicJwk] : [signingKey.publicJwk];
      return { keys };
    },
  );
}

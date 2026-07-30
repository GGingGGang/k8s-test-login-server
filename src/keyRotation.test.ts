import type { Redis } from "ioredis";
import { importJWK, jwtVerify } from "jose";
import type { Pool } from "mysql2/promise";
import { describe, expect, it } from "vitest";

import { buildApp } from "./router.js";
import { generateTestSigningKey } from "./test-support/signing-key.js";
import { signAccessToken } from "./tokens.js";
import type { TokenEnv } from "./tokens.js";

// buildApp() never touches pool/redis for the routes exercised here (JWKS is
// pure key material, signAccessToken bypasses /login entirely) — same stub
// pattern as router.test.ts.
const stubPool = {} as Pool;
const stubRedis = {} as Redis;
const tokenEnv: TokenEnv = { issuer: "auth.test", accessTtlSeconds: 3600, refreshTtlSeconds: 1_209_600 };

// Rehearses the key rotation runbook (../PLAN.md §6: "새 kid를 JWKS 에 24h
// 먼저 추가 후 서명 전환, 구 키는 access TTL 경과 후 제거") and its 4M DoD
// ("회전 중 core 검증 무중단") — without a real cluster: two in-process app
// instances model "before cutover" and "after cutover", and a token minted
// against the first must still verify against the second's JWKS.
describe("key rotation (kid 2개 공존)", () => {
  it("pre-cutover: both the active and the next key are independently published", async () => {
    const current = await generateTestSigningKey();
    const next = await generateTestSigningKey();

    const app = buildApp({ pool: stubPool, redis: stubRedis, signingKey: current, secondaryKey: next });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    expect(response.statusCode).toBe(200);

    const jwks = response.json() as { keys: Array<Record<string, unknown>> };
    expect(jwks.keys.map((k) => k.kid).sort()).toEqual([current.kid, next.kid].sort());
    expect(jwks.keys.every((k) => k.d === undefined)).toBe(true); // public keys only

    await app.close();
  });

  it("without a secondary key, JWKS exposes exactly one key (no rotation in progress)", async () => {
    const signingKey = await generateTestSigningKey();
    const app = buildApp({ pool: stubPool, redis: stubRedis, signingKey });
    await app.ready();

    const response = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    expect((response.json() as { keys: unknown[] }).keys).toHaveLength(1);

    await app.close();
  });

  it("a token signed before cutover still verifies against the post-cutover JWKS", async () => {
    const oldKey = await generateTestSigningKey();
    const newKey = await generateTestSigningKey();

    // Pre-cutover: sign with oldKey (newKey has already been published
    // elsewhere for 24h per the runbook — not re-tested here, covered by
    // the first case above).
    const { token: oldToken } = await signAccessToken("user-old", oldKey, tokenEnv);

    // Cutover: signing flips to newKey; oldKey moves into the secondary
    // slot so its still-unexpired tokens keep verifying.
    const postCutoverApp = buildApp({
      pool: stubPool,
      redis: stubRedis,
      signingKey: newKey,
      secondaryKey: oldKey,
    });
    await postCutoverApp.ready();

    const jwksResponse = await postCutoverApp.inject({ method: "GET", url: "/.well-known/jwks.json" });
    const jwks = jwksResponse.json() as { keys: Array<Record<string, unknown>> };

    // Reproduce core's verification path: resolve the token's kid against
    // the JWKS response, then jose.jwtVerify with the matching public key.
    const oldKeyJwk = jwks.keys.find((k) => k.kid === oldKey.kid);
    expect(oldKeyJwk).toBeDefined();
    const oldPublicKey = await importJWK(oldKeyJwk as Parameters<typeof importJWK>[0], "ES256");

    const { payload } = await jwtVerify(oldToken, oldPublicKey, { issuer: tokenEnv.issuer });
    expect(payload.sub).toBe("user-old");

    // A freshly signed token verifies against the new (now-active) key too.
    const { token: newToken } = await signAccessToken("user-new", newKey, tokenEnv);
    const newKeyJwk = jwks.keys.find((k) => k.kid === newKey.kid);
    expect(newKeyJwk).toBeDefined();
    const newPublicKey = await importJWK(newKeyJwk as Parameters<typeof importJWK>[0], "ES256");

    const { payload: newPayload } = await jwtVerify(newToken, newPublicKey, { issuer: tokenEnv.issuer });
    expect(newPayload.sub).toBe("user-new");

    await postCutoverApp.close();
  });
});

/**
 * The JWKS resolver is the one network-facing piece of identity
 * verification, so these tests are about its bounds: cache size, TTL, and
 * the unknown-`kid` refetch limiter that keeps an attacker from turning
 * "unknown kid" into a request against the IdP per token.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createJwksResolver, verifyJwt, type JsonWebKeyLike } from "./identity-jwt.js";

async function publicJwk(kid: string): Promise<{ jwk: JsonWebKeyLike; privateKey: CryptoKey }> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKeyLike;
  return { jwk: { ...jwk, kid }, privateKey: pair.privateKey };
}

const enc = new TextEncoder();
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function mintEdDSA(privateKey: CryptoKey, kid: string, payload: Record<string, unknown>): Promise<string> {
  const h = b64url(enc.encode(JSON.stringify({ alg: "EdDSA", kid })));
  const p = b64url(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`;
}

/** A fake IdP: rotates keys, fails on demand, counts requests. */
function idp(initial: JsonWebKeyLike[]) {
  let keys = initial;
  let status = 200;
  let body: string | undefined;
  let calls = 0;
  const fetch: typeof globalThis.fetch = async () => {
    calls++;
    return new Response(body ?? JSON.stringify({ keys }), { status });
  };
  return {
    fetch,
    get calls() { return calls; },
    rotate(next: JsonWebKeyLike[]) { keys = next; },
    fail(code: number) { status = code; },
    respondWith(raw: string) { body = raw; },
  };
}

function clock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance(ms: number) { t += ms; } };
}

describe("createJwksResolver — caching", () => {
  it("fetches once and serves every later lookup from cache", async () => {
    const a = await publicJwk("a");
    const server = idp([a.jwk]);
    const resolver = createJwksResolver({ jwksUri: "https://idp/keys", fetch: server.fetch });
    for (let i = 0; i < 5; i++) {
      const key = await resolver({ alg: "EdDSA", kid: "a" });
      assert.equal(key?.alg, "EdDSA");
      assert.equal(key?.kid, "a");
    }
    assert.equal(server.calls, 1);
    assert.deepEqual(resolver.stats(), { cachedKeys: 1, fetches: 1, throttledRefetches: 0 });
  });

  it("bounds the cache at maxKeys, keeping the newest", async () => {
    const jwks = await Promise.all(["k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"].map(publicJwk));
    const server = idp(jwks.map((k) => k.jwk));
    const resolver = createJwksResolver({ jwksUri: "https://idp/keys", fetch: server.fetch, maxKeys: 3 });
    await resolver({ alg: "EdDSA", kid: "k8" });
    assert.equal(resolver.stats().cachedKeys, 3);
    assert.ok(await resolver({ alg: "EdDSA", kid: "k8" }));
    assert.ok(await resolver({ alg: "EdDSA", kid: "k6" }));
    assert.equal(server.calls, 1);
  });

  it("rejects a non-positive maxKeys", () => {
    assert.throws(() => createJwksResolver({ jwksUri: "u", fetch: async () => new Response("{}"), maxKeys: 0 }), /maxKeys/);
    assert.throws(() => createJwksResolver({ jwksUri: "u", fetch: async () => new Response("{}"), maxKeys: 1.5 }), /maxKeys/);
  });

  it("expires keys after cacheTtlMs and refetches", async () => {
    const a = await publicJwk("a");
    const server = idp([a.jwk]);
    const c = clock();
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch, cacheTtlMs: 1_000, now: c.now });
    await resolver({ alg: "EdDSA", kid: "a" });
    c.advance(999);
    await resolver({ alg: "EdDSA", kid: "a" });
    assert.equal(server.calls, 1);
    c.advance(30_001); // past the TTL and past the cooldown
    await resolver({ alg: "EdDSA", kid: "a" });
    assert.equal(server.calls, 2);
  });

  it("skips keys it cannot use without failing the document", async () => {
    const a = await publicJwk("a");
    const server = idp([{ kty: "EC", crv: "P-521", kid: "p521", x: "x", y: "y" }, { ...a.jwk, use: "enc", kid: "enc" }, a.jwk]);
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch });
    assert.ok(await resolver({ alg: "EdDSA", kid: "a" }));
    assert.equal(resolver.stats().cachedKeys, 1);
  });

  it("clear() drops the cache", async () => {
    const a = await publicJwk("a");
    const server = idp([a.jwk]);
    const c = clock();
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch, now: c.now });
    await resolver({ alg: "EdDSA", kid: "a" });
    resolver.clear();
    assert.equal(resolver.stats().cachedKeys, 0);
    c.advance(60_000);
    await resolver({ alg: "EdDSA", kid: "a" });
    assert.equal(server.calls, 2);
  });
});

describe("createJwksResolver — unknown kid refetch is rate-limited", () => {
  it("refetches once for an unknown kid and picks up a rotation", async () => {
    const a = await publicJwk("a");
    const b = await publicJwk("b");
    const server = idp([a.jwk]);
    const c = clock();
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch, now: c.now });
    await resolver({ alg: "EdDSA", kid: "a" });
    c.advance(30_000);
    server.rotate([a.jwk, b.jwk]);
    const key = await resolver({ alg: "EdDSA", kid: "b" });
    assert.equal(key?.kid, "b");
    assert.equal(server.calls, 2);
  });

  it("cooldown: unknown kids inside minRefetchIntervalMs cost no request", async () => {
    const a = await publicJwk("a");
    const server = idp([a.jwk]);
    const c = clock();
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch, minRefetchIntervalMs: 30_000, now: c.now });
    await resolver({ alg: "EdDSA", kid: "a" });
    for (let i = 0; i < 100; i++) {
      c.advance(100);
      assert.equal(await resolver({ alg: "EdDSA", kid: `attacker-${i}` }), undefined);
    }
    assert.equal(server.calls, 1);
    assert.equal(resolver.stats().throttledRefetches, 100);
  });

  it("budget: a slow drip that waits out the cooldown is capped per window", async () => {
    const a = await publicJwk("a");
    const server = idp([a.jwk]);
    const c = clock();
    const resolver = createJwksResolver({
      jwksUri: "u", fetch: server.fetch, now: c.now,
      minRefetchIntervalMs: 1_000, maxRefetchesPerWindow: 3, refetchWindowMs: 60_000, cacheTtlMs: 600_000,
    });
    await resolver({ alg: "EdDSA", kid: "a" }); // cold fetch: 1 request, not budgeted
    for (let i = 0; i < 10; i++) {
      c.advance(1_000);
      await resolver({ alg: "EdDSA", kid: `drip-${i}` });
    }
    // 1 cold + 3 budgeted refetches; the other 7 refused.
    assert.equal(server.calls, 4);
    assert.equal(resolver.stats().throttledRefetches, 7);
    // The window slides: once the earliest refetch ages out, one more is allowed.
    c.advance(60_000);
    await resolver({ alg: "EdDSA", kid: "later" });
    assert.equal(server.calls, 5);
  });

  it("coalesces concurrent unknown-kid misses onto one request", async () => {
    const a = await publicJwk("a");
    const server = idp([a.jwk]);
    const c = clock();
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch, now: c.now });
    await resolver({ alg: "EdDSA", kid: "a" });
    c.advance(60_000);
    await Promise.all(Array.from({ length: 25 }, (_, i) => resolver({ alg: "EdDSA", kid: `burst-${i}` })));
    assert.equal(server.calls, 2);
  });

  it("a known kid never triggers a refetch even while the limiter is hot", async () => {
    const a = await publicJwk("a");
    const server = idp([a.jwk]);
    const c = clock();
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch, now: c.now });
    await resolver({ alg: "EdDSA", kid: "a" });
    await resolver({ alg: "EdDSA", kid: "nope" });
    assert.ok(await resolver({ alg: "EdDSA", kid: "a" }));
    assert.equal(server.calls, 1);
  });
});

describe("createJwksResolver — failures surface distinctly", () => {
  it("a non-2xx response is a resolution failure, not an unknown kid", async () => {
    const a = await publicJwk("a");
    const server = idp([a.jwk]);
    server.fail(503);
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch });
    await assert.rejects(resolver({ alg: "EdDSA", kid: "a" }), /returned 503/);

    const token = await mintEdDSA(a.privateKey, "a", { sub: "x", exp: 4_000_000_000 });
    const result = await verifyJwt(token, { resolveKey: resolver, now: 1 });
    assert.equal(result.valid, false);
    assert.equal(!result.valid && result.reason, "Key resolution failed: JWKS endpoint returned 503");
  });

  it("a document with no `keys` array is a resolution failure", async () => {
    const server = idp([]);
    server.respondWith('{"nope":true}');
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch });
    await assert.rejects(resolver({ alg: "EdDSA", kid: "a" }), /no `keys` array/);
  });

  it("a failing IdP is rate-limited too, and the failure is what callers see while throttled", async () => {
    const server = idp([]);
    server.fail(500);
    const c = clock();
    const resolver = createJwksResolver({ jwksUri: "u", fetch: server.fetch, now: c.now, minRefetchIntervalMs: 30_000 });
    await assert.rejects(resolver({ alg: "EdDSA", kid: "a" }), /returned 500/);
    for (let i = 0; i < 10; i++) {
      c.advance(1_000);
      await assert.rejects(resolver({ alg: "EdDSA", kid: "a" }), /returned 500/);
    }
    assert.equal(server.calls, 1);
    assert.equal(resolver.stats().throttledRefetches, 10);
    // Recovery: once the cooldown lapses the next miss really does retry.
    server.fail(200);
    c.advance(30_000);
    assert.equal(await resolver({ alg: "EdDSA", kid: "a" }), undefined);
    assert.equal(server.calls, 2);
  });
});

describe("createJwksResolver — end to end with verifyJwt", () => {
  it("verifies a token whose key arrives via rotation", async () => {
    const old = await publicJwk("2025");
    const fresh = await publicJwk("2026");
    const server = idp([old.jwk]);
    const c = clock();
    const resolveKey = createJwksResolver({ jwksUri: "u", fetch: server.fetch, now: c.now });
    const opts = { resolveKey, expectedIssuer: "idp", expectedAudience: "me", now: 1_800_000_000 };
    const payload = { iss: "idp", sub: "agent", aud: "me", exp: 1_800_000_300 };

    assert.equal((await verifyJwt(await mintEdDSA(old.privateKey, "2025", payload), opts)).valid, true);
    c.advance(30_000);
    const early = await verifyJwt(await mintEdDSA(fresh.privateKey, "2026", payload), opts);
    assert.equal(!early.valid && early.reason, "No key resolved for kid");
    assert.equal(server.calls, 2); // one refetch — the key really is not there yet

    c.advance(30_000);
    server.rotate([old.jwk, fresh.jwk]);
    assert.equal((await verifyJwt(await mintEdDSA(fresh.privateKey, "2026", payload), opts)).valid, true);
    assert.equal(server.calls, 3);
  });
});

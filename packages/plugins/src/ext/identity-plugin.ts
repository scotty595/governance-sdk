/**
 * Externally issued identity, as a plugin.
 *
 * Registers a verifier under `kernel.registerVerifier("identity", …)` so a host
 * can reach it with `gov.getVerifier("identity")`. The kernel does not call it:
 * the policy engine is synchronous and zero-dependency, so it cannot fetch a
 * JWKS or run `crypto.subtle.verify` mid-evaluation. The host verifies, sets
 * two booleans on the enforcement context, and `require_signed_identity` reads
 * them. That seam is the easiest thing here to get wrong, so the verifier
 * returns those booleans ready-made rather than a result you have to interpret.
 *
 * @example
 * ```ts
 * import { governance } from 'governance-sdk';
 * import { createJwksResolver, verifyJwt } from 'governance-sdk/identity-jwt';
 * import { identityPlugin } from 'governance-sdk/ext/identity';
 *
 * const resolveKey = createJwksResolver({ jwksUri: 'https://login.example.com/keys' });
 * const gov = governance({ policy: 'strict' });
 * await gov.use(identityPlugin({
 *   verifier: (token) => verifyJwt(token, {
 *     resolveKey,
 *     expectedIssuer: 'https://login.example.com/',
 *     expectedAudience: 'orders-api',
 *   }),
 * }));
 *
 * // …then, per request, in the host. Importing this module is what types
 * // `getVerifier('identity')`; without it the kernel returns `unknown`.
 * const identity = gov.getVerifier?.('identity');
 * if (!identity) throw new Error('identity plugin not installed');
 * const check = await identity.verify(bearerToken, { tool: 'refund' });
 *
 * const decision = await gov.enforce({
 *   agentId: check.verified ? check.agentId : 'unknown',
 *   action: 'tool_call',
 *   tool: 'refund',
 *   // `check.context` is exactly the fields `require_signed_identity` reads:
 *   // identityVerified, identityCapabilityMatch, identityFailureReason. Spread
 *   // it BEFORE enforce(), on every request — a context with
 *   // `identityVerified` left undefined fails closed, but records nothing
 *   // useful about why.
 *   ...check.context,
 * });
 * ```
 */

import type { GovernancePlugin, KernelHandle } from "@governance-sdk/core/plugin.js";
import type { EnforcementContext } from "@governance-sdk/core/policy.js";
import type { VerifyJwtIdentity } from "../identity-jwt.js";

declare module "@governance-sdk/core/plugin.js" {
  interface VerifierRegistry {
    /** Registered by `identityPlugin()`. */
    identity: RegisteredIdentityVerifier;
  }
}

/** What `verifyJwt` and `verifyJwtSvid` both return, structurally. */
export type ExternalIdentityResult =
  | { valid: true; agentId: string; identity: VerifyJwtIdentity }
  | { valid: false; reason: string };

/** Verifies one bearer token. Bind your verifier's options into it. */
export type ExternalIdentityVerifier = (token: string) => Promise<ExternalIdentityResult>;

/** Per-request facts the capability check needs. */
export interface IdentityVerifyContext {
  /** The tool this request wants to call, for capability binding. */
  tool?: string;
}

/**
 * Exactly the `EnforcementContext` fields `require_signed_identity` reads.
 * Typed against the kernel's own context, so a renamed field breaks here at
 * compile time instead of silently failing closed in production.
 */
export type IdentityContextFields = Pick<
  EnforcementContext,
  "identityVerified" | "identityCapabilityMatch" | "identityFailureReason"
>;

export type IdentityCheck =
  | {
      verified: true;
      /** From the token's agent-id claim — use it as `enforce({ agentId })`. */
      agentId: string;
      identity: VerifyJwtIdentity;
      /** Spread into `gov.enforce()`. */
      context: IdentityContextFields;
    }
  | { verified: false; reason: string; context: IdentityContextFields };

/** What `gov.getVerifier("identity")` returns once this plugin is installed. */
export interface RegisteredIdentityVerifier {
  /** Discriminator, so a host can be sure what it fished out of the kernel. */
  readonly kind: "identity";
  /** Verify a bearer token and produce the context fields for `enforce()`. */
  verify(token: string, context?: IdentityVerifyContext): Promise<IdentityCheck>;
}

export interface IdentityPluginOptions {
  /**
   * The verifier. Usually a closure over {@link verifyJwt} or
   * {@link verifyJwtSvid} with your issuer, audience and key resolver bound in.
   * To accept more than one IdP, dispatch inside this function — the kernel
   * holds one verifier per kind, so installing two identity plugins leaves
   * only the last one reachable.
   */
  verifier: ExternalIdentityVerifier;
  /**
   * Decide whether a verified identity may call `tool`. Default: the tool name
   * must appear in the token's capabilities. Override when your IdP's scopes
   * are not tool names (`orders.write` vs `refund`).
   */
  matchCapability?: (tool: string, capabilities: string[]) => boolean;
  /**
   * Write an `identity_verification` audit event per check, carrying the
   * delegation chain — the on-behalf-of record of who authorised what.
   * Default true.
   */
  audit?: boolean;
}

/** Version of this plugin, not of any IdP it talks to. */
const PLUGIN_VERSION = "1.0.0";

/**
 * Install an externally issued identity verifier.
 *
 * `gov.unuse("identity/external")` removes it; the kernel rolls the
 * registration back through the disposer it returned.
 */
export function identityPlugin(options: IdentityPluginOptions): GovernancePlugin {
  const { verifier, matchCapability = (tool, caps) => caps.includes(tool), audit = true } = options;
  if (typeof verifier !== "function") {
    throw new TypeError("identityPlugin: options.verifier must be a function");
  }

  return {
    id: "identity/external",
    version: PLUGIN_VERSION,
    requires: { core: "^0.22.0", capabilities: ["verifiers"] },

    install(kernel: KernelHandle): void {
      const registered: RegisteredIdentityVerifier = {
        kind: "identity",
        async verify(token: string, context: IdentityVerifyContext = {}): Promise<IdentityCheck> {
          let result: ExternalIdentityResult;
          try {
            result = await verifier(token);
          } catch (err) {
            // A verifier that throws (an IdP outage, say) is a failed
            // verification, not an exception into the host's request path.
            // The host still gets `identityVerified: false`, which fails closed.
            result = { valid: false, reason: `Verifier threw: ${(err as Error).message}` };
          }

          if (!result.valid) {
            if (audit) await logFailure(kernel, result.reason);
            return {
              verified: false,
              reason: result.reason,
              context: { identityVerified: false, identityFailureReason: result.reason },
            };
          }

          // "No tool on the request" counts as a match — the capability check
          // is about narrowing a verified identity, not about denying one.
          const identityCapabilityMatch =
            context.tool === undefined ? true : matchCapability(context.tool, result.identity.capabilities);
          if (audit) await logSuccess(kernel, result, context, identityCapabilityMatch);
          return {
            verified: true,
            agentId: result.agentId,
            identity: result.identity,
            context: { identityVerified: true, identityCapabilityMatch },
          };
        },
      };

      kernel.registerVerifier("identity", registered);
    },
  };
}

// ─── Audit ───────────────────────────────────────────────────

async function logSuccess(
  kernel: KernelHandle,
  result: { agentId: string; identity: VerifyJwtIdentity },
  context: IdentityVerifyContext,
  capabilityMatch: boolean,
): Promise<void> {
  const { identity } = result;
  await safeLog(kernel, {
    agentId: result.agentId,
    eventType: "identity_verification",
    outcome: capabilityMatch ? "success" : "failure",
    severity: capabilityMatch ? "info" : "warning",
    detail: {
      issuer: identity.issuer,
      subject: identity.subject,
      audience: identity.audience,
      algorithm: identity.algorithm,
      kid: identity.kid,
      jti: identity.jti,
      capabilities: identity.capabilities,
      capabilityMatch,
      // The on-behalf-of chain: who authorised what. Recorded even on a
      // capability miss, because that is exactly the event worth reviewing.
      delegationChain: identity.delegation?.chain ?? [],
      authorizedParty: identity.delegation?.azp,
      ...(context.tool !== undefined ? { tool: context.tool } : {}),
    },
  });
}

async function logFailure(kernel: KernelHandle, reason: string): Promise<void> {
  await safeLog(kernel, {
    agentId: "unknown",
    eventType: "identity_verification",
    outcome: "failure",
    severity: "warning",
    detail: { reason },
  });
}

/** Auditing must never turn a verification into a thrown request. */
async function safeLog(
  kernel: KernelHandle,
  event: Parameters<KernelHandle["audit"]["log"]>[0],
): Promise<void> {
  try {
    await kernel.audit.log(event);
  } catch {
    // Swallowed on purpose: the sink contract already routes write failures
    // to `onAuditError`, and a failed audit write must not deny a request the
    // policy engine has not been asked about yet.
  }
}

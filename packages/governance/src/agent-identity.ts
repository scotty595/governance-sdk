/**
 * governance-sdk — Agent Identity Primitives (HMAC-SHA256)
 *
 * Shared-secret agent identity using HMAC-SHA256 via Web Crypto API.
 * Zero dependencies. Produces verifiable identity tokens and fingerprints.
 *
 * @deprecated Use `governance-sdk/agent-identity-ed25519` instead
 * (`signAgentIdentity` / `verifyAgentIdentity`). Public-key identity needs no
 * shared secret on the verifier, and that module supports key pinning and
 * rotation, `aud` / `iss` binding and replay protection. This module is kept
 * so existing callers keep compiling; it will be removed in a future major.
 *
 * **Token format v2.** The HMAC now covers *every* claim — the agent identity
 * fields, `agentId`, `issuedAt` and `expiresAt`. v1 tokens signed only the
 * agent fields + `issuedAt` and carried `expiresAt` unsigned, so an expired
 * token could be revived by rewriting or deleting `expiresAt`. v1 tokens are
 * rejected outright (`reason` starts with "Unsupported token version");
 * re-issue them.
 *
 * @example
 * ```ts
 * import { createAgentIdentity } from 'governance-sdk/agent-identity';
 *
 * const identity = createAgentIdentity(process.env.IDENTITY_SECRET); // ≥ 16 bytes
 * const token = await identity.issueToken({ id: 'agent-1', name: 'sales-bot', owner: 'team-a' });
 * const valid = await identity.verifyToken(token, { id: 'agent-1', name: 'sales-bot', owner: 'team-a' });
 * const fingerprint = await identity.getFingerprint({ id: 'agent-1', name: 'sales-bot' });
 * ```
 */

import { hmacSha256, deepSortKeys, constantTimeEqualHex } from "./audit-integrity.js";

// ─── Types ───────────────────────────────────────────────────

/** Current token format version. Only tokens carrying this version verify. */
export const AGENT_IDENTITY_TOKEN_VERSION = 2 as const;

/** Minimum HMAC secret length, in UTF-8 bytes. */
export const MIN_SIGNING_KEY_BYTES = 16;

/**
 * Minimal agent fields used for identity derivation
 * @deprecated See module-level notice — prefer `governance-sdk/agent-identity-ed25519`.
 */
export interface AgentIdentityInput {
  id: string;
  name: string;
  owner?: string;
  version?: string;
  framework?: string;
}

/**
 * Issued identity token with metadata
 * @deprecated See module-level notice — prefer `governance-sdk/agent-identity-ed25519`.
 */
export interface AgentIdentityToken {
  /** Token format version — always {@link AGENT_IDENTITY_TOKEN_VERSION}. */
  v: typeof AGENT_IDENTITY_TOKEN_VERSION;
  /** HMAC-SHA256 over the canonical form of every other claim below (plus the agent fields) */
  signature: string;
  /** Agent ID this token was issued for */
  agentId: string;
  /** ISO timestamp of token issuance */
  issuedAt: string;
  /** ISO timestamp of token expiry (if configured) */
  expiresAt?: string;
  /** Short fingerprint (first 16 hex chars of signature) */
  fingerprint: string;
}

/** Verification result */
export interface VerificationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Configuration for agent identity
 * @deprecated See module-level notice — prefer `governance-sdk/agent-identity-ed25519`.
 */
export interface AgentIdentityConfig {
  /** Token expiry duration in milliseconds (default: no expiry) */
  tokenTtlMs?: number;
}

// ─── Implementation ─────────────────────────────────────────

/**
 * Create an HMAC-SHA256 agent identity issuer/verifier bound to a shared secret.
 *
 * @deprecated Use `createEd25519Identity` / `signAgentIdentity` /
 * `verifyAgentIdentity` from `governance-sdk/agent-identity-ed25519`.
 *
 * @param signingKey Shared secret. Must be non-empty and at least
 *   {@link MIN_SIGNING_KEY_BYTES} UTF-8 bytes; shorter secrets throw.
 */
export function createAgentIdentity(signingKey: string, config: AgentIdentityConfig = {}) {
  if (typeof signingKey !== "string" || signingKey.length === 0) {
    throw new Error("Signing key is required for agent identity");
  }
  const keyBytes = new TextEncoder().encode(signingKey).length;
  if (keyBytes < MIN_SIGNING_KEY_BYTES) {
    throw new Error(
      `Signing key must be at least ${MIN_SIGNING_KEY_BYTES} bytes (got ${keyBytes}) — use a random secret, not a short passphrase`,
    );
  }

  return {
    /**
     * Issue a verifiable identity token for an agent.
     * The HMAC covers the agent's identity fields and every token claim
     * (`agentId`, `issuedAt`, `expiresAt`), so none can be altered after issue.
     * @deprecated See module-level notice.
     */
    async issueToken(agent: AgentIdentityInput): Promise<AgentIdentityToken> {
      const issuedAt = new Date().toISOString();
      const expiresAt = config.tokenTtlMs
        ? new Date(Date.now() + config.tokenTtlMs).toISOString()
        : undefined;
      const signature = await hmacSha256(signingKey, canonicalizeClaims(agent, issuedAt, expiresAt));

      return {
        v: AGENT_IDENTITY_TOKEN_VERSION,
        signature,
        agentId: agent.id,
        issuedAt,
        ...(expiresAt !== undefined ? { expiresAt } : {}),
        fingerprint: signature.slice(0, 16),
      };
    },

    /**
     * Verify an identity token against an agent's current identity.
     * Recomputes the HMAC over all claims and compares in constant time, then
     * enforces expiry from the (now signed) `expiresAt` claim.
     * @deprecated See module-level notice.
     */
    async verifyToken(token: AgentIdentityToken, agent: AgentIdentityInput): Promise<VerificationResult> {
      if (!isTokenShaped(token)) {
        return { valid: false, reason: "Malformed token" };
      }
      if (token.v !== AGENT_IDENTITY_TOKEN_VERSION) {
        return {
          valid: false,
          reason:
            `Unsupported token version: expected v${AGENT_IDENTITY_TOKEN_VERSION}. ` +
            "v1 tokens did not sign their expiry and are no longer accepted — re-issue the token",
        };
      }
      if (token.agentId !== agent.id) {
        return { valid: false, reason: "Token agent ID does not match" };
      }

      const expectedSignature = await hmacSha256(
        signingKey,
        canonicalizeClaims(agent, token.issuedAt, token.expiresAt),
      );
      if (!constantTimeEqualHex(expectedSignature, token.signature)) {
        return { valid: false, reason: "Signature mismatch — agent identity may have been tampered with" };
      }

      // Expiry is checked AFTER the signature so a rewritten/deleted expiresAt
      // fails as a signature mismatch rather than being trusted.
      if (token.expiresAt !== undefined) {
        const expiresAtMs = Date.parse(token.expiresAt);
        if (Number.isNaN(expiresAtMs) || expiresAtMs < Date.now()) {
          return { valid: false, reason: "Token has expired" };
        }
      }

      return { valid: true };
    },

    /**
     * Get a deterministic fingerprint for an agent (first 16 hex chars of identity hash).
     * Useful for human-readable agent identification in logs and dashboards.
     * Unchanged by the v2 token format — fingerprints remain stable.
     * @deprecated See module-level notice.
     */
    async getFingerprint(agent: AgentIdentityInput): Promise<string> {
      const hash = await hmacSha256(signingKey, canonicalizeAgent(agent));
      return hash.slice(0, 16);
    },
  };
}

// ─── Utilities ──────────────────────────────────────────────

/** Canonical serialization of agent identity fields (deterministic, sorted) */
function canonicalizeAgent(agent: AgentIdentityInput): string {
  return JSON.stringify(agentFields(agent));
}

function agentFields(agent: AgentIdentityInput): unknown {
  return deepSortKeys({
    id: agent.id,
    name: agent.name,
    owner: agent.owner ?? "",
    version: agent.version ?? "",
    framework: agent.framework ?? "",
  });
}

/**
 * Canonical signed payload for a v2 token: version + agent fields + every
 * token claim. `expiresAt` is bound as `null` when absent so that deleting
 * the claim from a token changes the signed bytes.
 */
function canonicalizeClaims(agent: AgentIdentityInput, issuedAt: string, expiresAt: string | undefined): string {
  return JSON.stringify(
    deepSortKeys({
      v: AGENT_IDENTITY_TOKEN_VERSION,
      agent: agentFields(agent),
      agentId: agent.id,
      issuedAt,
      expiresAt: expiresAt ?? null,
    }),
  );
}

/** Structural check — untrusted tokens arrive over the wire as arbitrary JSON. */
function isTokenShaped(token: unknown): token is AgentIdentityToken {
  if (token === null || typeof token !== "object") return false;
  const t = token as Record<string, unknown>;
  return (
    typeof t.signature === "string" &&
    typeof t.agentId === "string" &&
    typeof t.issuedAt === "string" &&
    (t.expiresAt === undefined || typeof t.expiresAt === "string")
  );
}

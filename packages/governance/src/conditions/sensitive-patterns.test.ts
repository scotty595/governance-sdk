import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { EnforcementContext } from "../policy.js";
import {
  getSensitivePatterns,
  luhnValid,
  matchesSensitivePattern,
  type SensitivePattern,
} from "./sensitive-patterns";
import { evaluateSensitiveDataFilter } from "./postprocess";
import { maskSensitiveData } from "../mask";

const ctx = (outputText: string): EnforcementContext => ({ agentId: "a", action: "tool_call", outputText });
const byId = (id: string): SensitivePattern => getSensitivePatterns([id])[0];

describe("sensitive patterns — false-positive corpus yields zero masks", () => {
  const corpus: Array<[string, string]> = [
    ["git SHA-1 in prose", "Fixed in commit 3f2a9c1e7b4d8a6f0c5e2b9d1a7f3c8e6b4d2a90 on main"],
    ["git SHA-1 in log line", "commit 0123456789abcdef0123456789abcdef01234567 (HEAD -> main)"],
    ["semver with pre-release and build", "Upgraded from 1.2.3 to 1.2.4-beta.1+build.5"],
    ["four-part version strings", "Assembly version 4.0.30319.42000 and driver v10.0.19041.1"],
    ["v-prefixed version and browser UA", "v1.2.3.4 shipped; Chrome/120.0.6099.109 tested"],
    ["release label", "See the release 2.10.4.1 notes and build 1.2.3.4-rc1"],
    ["order ids", "Order ORD-2026-000123 and ORD-123-456-7890 shipped"],
    ["ISO timestamps", "Created 2026-09-04T10:22:33.123Z, updated 2026-09-04 10:22:33"],
    ["UUIDs", "request 9b2d1f6e-3c4a-4e8b-9f0d-2a6c7b8e9d10 traced"],
    ["10-digit invoice numbers", "Invoice 1234567890 and reference 0987654321 paid"],
    ["16-digit id failing Luhn", "Tracking number 4000000000000001 in transit"],
    ["16-digit serial failing Luhn", "Serial 5100000000000000 registered"],
    ["image tag and Java version", "image nginx:1.25.3-alpine on Java 1.8.0_291"],
    ["user@host without a TLD", "ssh deploy@localhost then user@buildbox"],
  ];
  for (const [name, text] of corpus) {
    it(name, () => {
      assert.equal(maskSensitiveData(text), text);
      assert.equal(evaluateSensitiveDataFilter(ctx(text)), false);
    });
  }
});

describe("sensitive patterns — true-positive corpus still masks", () => {
  const corpus: Array<{ name: string; id: string; text: string; secrets: string[] }> = [
    {
      name: "AWS key pair, labelled (credentials file)",
      id: "aws_secret",
      text: "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      secrets: ["AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
    },
    {
      name: "AWS key pair, bare but paired",
      id: "aws_secret",
      text: "creds: AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      secrets: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
    },
    {
      name: "AWS secret in JSON",
      id: "aws_secret",
      text: '{"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}',
      secrets: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
    },
    { name: "Luhn-valid Visa test card", id: "credit_card", text: "Card 4111111111111111 on file", secrets: ["4111111111111111"] },
    { name: "Luhn-valid dashed card", id: "credit_card", text: "Your card is 4242-4242-4242-4242 expiring 12/25", secrets: ["4242-4242-4242-4242"] },
    {
      name: "formatted US phone numbers",
      id: "phone_us",
      text: "Call (212) 555-0123, 212-555-0123, 212.555.0123 or +1 212 555 0123",
      secrets: ["(212) 555-0123", "212-555-0123", "212.555.0123", "+1 212 555 0123"],
    },
    { name: "email address", id: "email_address", text: "Contact jane.doe+billing@example.co.uk today", secrets: ["jane.doe+billing@example.co.uk"] },
    { name: "SSN", id: "ssn", text: "the customer's SSN is 123-45-6789.", secrets: ["123-45-6789"] },
    { name: "connection string", id: "postgres_uri", text: "postgres://admin:hunter2@db.internal:5432/crm", secrets: ["hunter2"] },
    { name: "IP addresses with port and CIDR", id: "ip_address", text: "listening on 10.0.0.5:8080 and 192.168.1.20/24", secrets: ["10.0.0.5", "192.168.1.20"] },
  ];
  for (const c of corpus) {
    it(c.name, () => {
      assert.equal(evaluateSensitiveDataFilter(ctx(c.text), [c.id]), true, `${c.id} did not fire`);
      const masked = maskSensitiveData(c.text);
      assert.ok(masked.includes("[REDACTED]"), `nothing masked: ${masked}`);
      for (const s of c.secrets) assert.ok(!masked.includes(s), `still visible: ${s} in ${masked}`);
    });
  }
});

describe("sensitive patterns — validate hook and precision rules", () => {
  it("luhnValid accepts valid and rejects invalid numbers", () => {
    assert.equal(luhnValid("4111111111111111"), true);
    assert.equal(luhnValid("4242 4242 4242 4242"), true);
    assert.equal(luhnValid("4111111111111112"), false);
    assert.equal(luhnValid("123"), false);
  });

  it("credit_card requires a Luhn-valid number", () => {
    const cc = byId("credit_card");
    assert.equal(matchesSensitivePattern(cc, "4111 1111 1111 1111"), true);
    assert.equal(matchesSensitivePattern(cc, "4000 0000 0000 0001"), false);
  });

  it("ip_address rejects octets above 255 and version-like context", () => {
    const ip = byId("ip_address");
    assert.equal(matchesSensitivePattern(ip, "host 10.0.0.1"), true);
    assert.equal(matchesSensitivePattern(ip, "host 256.0.0.1"), false);
    assert.equal(matchesSensitivePattern(ip, "host 999.1.1.1"), false);
    assert.equal(matchesSensitivePattern(ip, "version 1.2.3.4"), false);
    assert.equal(matchesSensitivePattern(ip, "Version: 1.2.3.4"), false);
    assert.equal(matchesSensitivePattern(ip, "1.2.3.4-beta"), false);
    assert.equal(matchesSensitivePattern(ip, "1.2.3.4.5"), false);
  });

  it("phone_us requires separators, +1, or a parenthesised area code", () => {
    const phone = byId("phone_us");
    assert.equal(matchesSensitivePattern(phone, "2125550123"), false);
    assert.equal(matchesSensitivePattern(phone, "212-5550123"), false);
    assert.equal(matchesSensitivePattern(phone, "(212)5550123"), true);
    assert.equal(matchesSensitivePattern(phone, "+12125550123"), true);
    assert.equal(matchesSensitivePattern(phone, "1-800-555-0199"), true);
  });

  it("aws_secret requires a secret label or a nearby AKIA key id", () => {
    const aws = byId("aws_secret");
    const token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    assert.equal(matchesSensitivePattern(aws, `value ${token}`), false);
    assert.equal(matchesSensitivePattern(aws, `secret=${token}`), true);
    assert.equal(matchesSensitivePattern(aws, `AWS secret key: ${token}`), true);
    assert.equal(matchesSensitivePattern(aws, `AKIAIOSFODNN7EXAMPLE / ${token}`), true);
    assert.equal(matchesSensitivePattern(aws, `the secret sauce ${"3f2a9c1e7b4d8a6f0c5e2b9d1a7f3c8e6b4d2a90"}`), false);
  });

  it("matchesSensitivePattern honours a custom validate hook", () => {
    const even: SensitivePattern = { id: "even", name: "Even", pattern: /\d{4}/, validate: (m) => Number(m) % 2 === 0 };
    assert.equal(matchesSensitivePattern(even, "ids 1235 and 1237"), false);
    assert.equal(matchesSensitivePattern(even, "ids 1235 and 1238"), true);
  });

  it("maskSensitiveData matches every pattern against the original text and merges spans", () => {
    // aws_key and aws_secret: the AKIA pairing context survives because
    // aws_key's redaction is not applied before aws_secret runs.
    assert.equal(
      maskSensitiveData("creds: AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
      "creds: [REDACTED] [REDACTED]",
    );
    // An email inside a connection string collapses into a single redaction.
    assert.equal(maskSensitiveData("db postgres://admin:hunter2@db.internal:5432/crm ok"), "db [REDACTED] ok");
    // A rejected candidate (Luhn-invalid) is left untouched next to a real hit.
    assert.equal(maskSensitiveData("4000000000000001 vs 4111111111111111"), "4000000000000001 vs [REDACTED]");
  });
});

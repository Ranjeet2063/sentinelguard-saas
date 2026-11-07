/* Authorized Protocol Quality Assurance & Formal Verification Test Suite */

import { describe, it, expect, beforeEach } from "vitest";
import crypto from "crypto";
import { buildServer, verifyWebhookSignature } from "../src/server.js";
import { globalStore } from "../src/db/store.js";
import { globalScanner, FileChange } from "../src/security/scanner.js";
import { MarketplaceWebhookPayload } from "../src/types/index.js";

const TEST_SECRET = "development-secret-key-12345";

describe("SentinelGuard GitHub Marketplace SaaS Suite", () => {
  beforeEach(() => {
    globalStore.clear();
  });

  describe("1. HMAC Webhook Signature Verification", () => {
    it("should accept valid HMAC SHA-256 signatures", () => {
      const payload = JSON.stringify({ action: "ping" });
      const hmac = crypto.createHmac("sha256", TEST_SECRET);
      const signature = `sha256=${hmac.update(payload).digest("hex")}`;

      const isValid = verifyWebhookSignature(payload, signature);
      expect(isValid).toBe(true);
    });

    it("should reject tampered or invalid signatures", () => {
      const payload = JSON.stringify({ action: "ping" });
      const fakeSignature = "sha256=1111222233334444555566667777888899990000";

      const isValid = verifyWebhookSignature(payload, fakeSignature);
      expect(isValid).toBe(false);
    });
  });

  describe("2. Marketplace Billing & Revenue Calculations", () => {
    it("should process Pro Plan purchase and compute exact 95% net payout", async () => {
      const app = buildServer();

      const purchasePayload: MarketplaceWebhookPayload = {
        action: "purchased",
        effective_date: new Date().toISOString(),
        sender: { login: "stellar-defi-corp", id: 101 },
        marketplace_purchase: {
          account: {
            login: "stellar-defi-corp",
            id: 101,
            type: "Organization",
          },
          billing_cycle: "monthly",
          unit_count: 1,
          plan: {
            id: 501,
            name: "Pro Plan",
            description: "Deep invariant analysis for private repos",
            monthly_price_in_cents: 2900, // $29.00
            yearly_price_in_cents: 29000,
            price_model: "flat-rate",
          },
        },
      };

      const res = await app.inject({
        method: "POST",
        url: "/api/github/webhook",
        headers: {
          "x-github-event": "marketplace_purchase",
          "content-type": "application/json",
        },
        payload: purchasePayload,
      });

      expect(res.statusCode).toBe(200);
      const json = JSON.parse(res.body);
      expect(json.success).toBe(true);
      expect(json.plan).toBe("PRO");
      expect(json.monthlyPriceUSD).toBe(29);

      // Verify Metrics Endpoint
      const metricsRes = await app.inject({
        method: "GET",
        url: "/metrics",
      });
      const metrics = JSON.parse(metricsRes.body);

      expect(metrics.financial.activeSubscribers).toBe(1);
      expect(metrics.financial.grossMRR_USD).toBe(29);
      expect(metrics.financial.githubFee5Percent_USD).toBeCloseTo(1.45, 2);
      expect(metrics.financial.netPayoutUSD).toBeCloseTo(27.55, 2);
      expect(metrics.financial.estimatedPayoutNPR).toBeGreaterThan(3000);
    });

    it("should handle subscription cancellation and revert to FREE tier", async () => {
      const app = buildServer();

      // First subscribe to Enterprise
      const subscribePayload: MarketplaceWebhookPayload = {
        action: "purchased",
        effective_date: new Date().toISOString(),
        sender: { login: "enterprise-user", id: 202 },
        marketplace_purchase: {
          account: { login: "enterprise-user", id: 202, type: "User" },
          billing_cycle: "monthly",
          unit_count: 1,
          plan: {
            id: 502,
            name: "Enterprise Plan",
            description: "Custom compliance",
            monthly_price_in_cents: 9900, // $99.00
            yearly_price_in_cents: 99000,
            price_model: "flat-rate",
          },
        },
      };

      await app.inject({
        method: "POST",
        url: "/api/github/webhook",
        headers: { "x-github-event": "marketplace_purchase", "content-type": "application/json" },
        payload: subscribePayload,
      });

      expect(globalStore.getAccount("enterprise-user").plan).toBe("ENTERPRISE");

      // Now cancel subscription
      const cancelPayload: MarketplaceWebhookPayload = {
        ...subscribePayload,
        action: "cancelled",
      };

      const res = await app.inject({
        method: "POST",
        url: "/api/github/webhook",
        headers: { "x-github-event": "marketplace_purchase", "content-type": "application/json" },
        payload: cancelPayload,
      });

      expect(res.statusCode).toBe(200);
      expect(globalStore.getAccount("enterprise-user").plan).toBe("FREE");
      expect(globalStore.getFinancialMetrics().grossMRR).toBe(0);
    });
  });

  describe("3. Security Invariant Scanner", () => {
    it("should flag leaked Stellar secret keys with CRITICAL severity", () => {
      const vulnerableFiles: FileChange[] = [
        {
          filename: "src/config.rs",
          patch: `@@ -1,3 +1,4 @@\n+// Adding production admin key\n+const ADMIN_KEY: &str = "SB3D4EF5GHIJKLMNOPQRSTUVWXYZ23456789ABCDEFGHIJKLMNOPQRSTUV";\n`,
        },
      ];

      const result = globalScanner.scanPullRequest("org/repo", 42, "FREE", vulnerableFiles);

      expect(result.passed).toBe(false);
      expect(result.criticalCount).toBe(1);
      expect(result.findings[0].ruleId).toBe("SEC-001");
      expect(result.findings[0].severity).toBe("CRITICAL");
    });

    it("should flag Soroban unhandled panic (.unwrap) in PRO tier", () => {
      const sorobanFiles: FileChange[] = [
        {
          filename: "contracts/vault/src/lib.rs",
          patch: `@@ -10,3 +10,4 @@\n+    let balance = env.storage().instance().get(&key).unwrap();\n`,
        },
      ];

      const result = globalScanner.scanPullRequest("stellar/vault", 12, "PRO", sorobanFiles);

      expect(result.passed).toBe(false);
      expect(result.highCount).toBe(1);
      expect(result.findings[0].ruleId).toBe("SOR-001");
      expect(result.findings[0].message).toContain("Explicit `.unwrap()` detected in Soroban contract");
    });

    it("should pass 100% clean code without false positives", () => {
      const cleanFiles: FileChange[] = [
        {
          filename: "contracts/token/src/lib.rs",
          patch: `@@ -1,5 +1,6 @@\n+pub fn query_balance(env: Env, owner: Address) -> Result<i128, Error> {\n+    owner.require_auth();\n+    Ok(100)\n+}`,
        },
      ];

      const result = globalScanner.scanPullRequest("stellar/token", 1, "PRO", cleanFiles);

      expect(result.passed).toBe(true);
      expect(result.totalFindings).toBe(0);
      expect(result.summary).toContain("Zero critical security invariant violations");
    });
  });
});

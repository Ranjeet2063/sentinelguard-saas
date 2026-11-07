/* Authorized Protocol Quality Assurance & Formal Verification Test Suite */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
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
      assert.equal(isValid, true);
    });

    it("should reject tampered or invalid signatures", () => {
      const payload = JSON.stringify({ action: "ping" });
      const fakeSignature = "sha256=1111222233334444555566667777888899990000";

      const isValid = verifyWebhookSignature(payload, fakeSignature);
      assert.equal(isValid, false);
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

      assert.equal(res.statusCode, 200);
      const json = JSON.parse(res.body);
      assert.equal(json.success, true);
      assert.equal(json.plan, "PRO");
      assert.equal(json.monthlyPriceUSD, 29);

      // Verify Metrics Endpoint
      const metricsRes = await app.inject({
        method: "GET",
        url: "/metrics",
      });
      const metrics = JSON.parse(metricsRes.body);

      assert.equal(metrics.financial.activeSubscribers, 1);
      assert.equal(metrics.financial.grossMRR_USD, 29);
      assert.ok(Math.abs(metrics.financial.githubFee5Percent_USD - 1.45) < 0.01);
      assert.ok(Math.abs(metrics.financial.netPayoutUSD - 27.55) < 0.01);
      assert.ok(metrics.financial.estimatedPayoutNPR > 3000);
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

      assert.equal(globalStore.getAccount("enterprise-user").plan, "ENTERPRISE");

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

      assert.equal(res.statusCode, 200);
      assert.equal(globalStore.getAccount("enterprise-user").plan, "FREE");
      assert.equal(globalStore.getFinancialMetrics().grossMRR, 0);
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

      assert.equal(result.passed, false);
      assert.equal(result.criticalCount, 1);
      assert.equal(result.findings[0].ruleId, "SEC-001");
      assert.equal(result.findings[0].severity, "CRITICAL");
    });

    it("should flag Soroban unhandled panic (.unwrap) in PRO tier", () => {
      const sorobanFiles: FileChange[] = [
        {
          filename: "contracts/vault/src/lib.rs",
          patch: `@@ -10,3 +10,4 @@\n+    let balance = env.storage().instance().get(&key).unwrap();\n`,
        },
      ];

      const result = globalScanner.scanPullRequest("stellar/vault", 12, "PRO", sorobanFiles);

      assert.equal(result.passed, false);
      assert.equal(result.highCount, 1);
      assert.equal(result.findings[0].ruleId, "SOR-001");
      assert.ok(result.findings[0].message.includes("Explicit `.unwrap()` detected in Soroban contract"));
    });

    it("should pass 100% clean code without false positives", () => {
      const cleanFiles: FileChange[] = [
        {
          filename: "contracts/token/src/lib.rs",
          patch: `@@ -1,5 +1,6 @@\n+pub fn query_balance(env: Env, owner: Address) -> Result<i128, Error> {\n+    owner.require_auth();\n+    Ok(100)\n+}`,
        },
      ];

      const result = globalScanner.scanPullRequest("stellar/token", 1, "PRO", cleanFiles);

      assert.equal(result.passed, true);
      assert.equal(result.totalFindings, 0);
      assert.ok(result.summary.includes("Zero critical security invariant violations"));
    });
  });
});

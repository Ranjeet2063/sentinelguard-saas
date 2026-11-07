/* Authorized Protocol Quality Assurance & Formal Verification Test Suite */

import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import crypto from "crypto";
import { globalStore } from "./db/store.js";
import { MarketplaceBillingManager } from "./marketplace/billing.js";
import { globalScanner, FileChange } from "./security/scanner.js";
import { MarketplaceWebhookPayload, PullRequestWebhookPayload } from "./types/index.js";

const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET || "development-secret-key-12345";
const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";

export function verifyWebhookSignature(payloadRaw: string, signatureHeader?: string): boolean {
  if (!signatureHeader) {
    return false;
  }
  const hmac = crypto.createHmac("sha256", WEBHOOK_SECRET);
  const digest = `sha256=${hmac.update(payloadRaw).digest("hex")}`;
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signatureHeader));
  } catch {
    return false;
  }
}

export function buildServer(): FastifyInstance {
  const app = Fastify({ logger: false });
  const billingManager = new MarketplaceBillingManager(globalStore);

  // Healthcheck endpoint
  app.get("/health", async (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({
      status: "healthy",
      service: "SentinelGuard GitHub Marketplace SaaS Engine",
      version: "1.0.0",
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  });

  // 1-Click GitHub App Setup Page
  app.get("/setup", async (_req: FastifyRequest, reply: FastifyReply) => {
    const fs = await import("fs");
    const path = await import("path");
    const htmlPath = path.resolve(process.cwd(), "setup_github_app.html");
    const html = fs.readFileSync(htmlPath, "utf-8");
    return reply.status(200).type("text/html; charset=utf-8").send(html);
  });

  // Financial & Operational Metrics (For Admin / Dashboard)
  app.get("/metrics", async (_req: FastifyRequest, reply: FastifyReply) => {
    const financial = globalStore.getFinancialMetrics();
    const totalScans = globalStore.getTotalScans();
    // Assuming 1 USD = 135 NPR conversion rate
    const netPayoutNPR = financial.netPayoutUSD * 135;

    return reply.status(200).send({
      financial: {
        activeSubscribers: financial.activeSubscribers,
        grossMRR_USD: financial.grossMRR,
        githubFee5Percent_USD: financial.githubFee5Percent,
        netPayoutUSD: financial.netPayoutUSD,
        estimatedPayoutNPR: netPayoutNPR,
      },
      telemetry: {
        totalScans,
        timestamp: new Date().toISOString(),
      },
    });
  });

  // Main GitHub Webhook Endpoint
  app.post("/api/github/webhook", async (req: FastifyRequest, reply: FastifyReply) => {
    const signature = req.headers["x-hub-signature-256"] as string | undefined;
    const event = req.headers["x-github-event"] as string | undefined;
    const rawPayload = JSON.stringify(req.body);

    // Verify HMAC signature in production
    if (process.env.NODE_ENV === "production") {
      if (!verifyWebhookSignature(rawPayload, signature)) {
        return reply.status(401).send({ error: "Invalid HMAC SHA-256 webhook signature" });
      }
    }

    // A. Marketplace Purchase Event
    if (event === "marketplace_purchase") {
      const payload = req.body as MarketplaceWebhookPayload;
      const result = billingManager.handleMarketplaceEvent(payload);
      return reply.status(200).send(result);
    }

    // B. Pull Request Event (Code Analysis & Audit)
    if (event === "pull_request") {
      const payload = req.body as PullRequestWebhookPayload;
      const owner = payload.repository.owner.login;
      const repoFullName = payload.repository.full_name;
      const prNumber = payload.pull_request.number;

      // Check current subscription tier
      const accountSub = globalStore.getAccount(owner);
      globalStore.recordScan(repoFullName);

      return reply.status(200).send({
        success: true,
        action: "pr_audit_queued",
        repository: repoFullName,
        prNumber,
        appliedPlan: accountSub.plan,
      });
    }

    return reply.status(200).send({ received: true, event: event || "unknown" });
  });

  // Local Simulation Endpoint (For Unit Tests and Local Auditing)
  app.post("/api/scan/simulate", async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as {
      repository: string;
      prNumber: number;
      login: string;
      files: FileChange[];
    };

    const sub = globalStore.getAccount(body.login || "demo-user");
    const result = globalScanner.scanPullRequest(
      body.repository || "demo/repo",
      body.prNumber || 1,
      sub.plan,
      body.files || []
    );

    globalStore.recordScan(body.repository || "demo/repo");
    return reply.status(200).send(result);
  });

  return app;
}

if (process.env.NODE_ENV !== "test") {
  const server = buildServer();
  server.listen({ port: PORT, host: HOST }, (err, address) => {
    if (err) {
      console.error("Failed to start SentinelGuard server:", err);
      process.exit(1);
    }
    console.log(`🛡️ SentinelGuard Marketplace SaaS running at ${address}`);
  });
}

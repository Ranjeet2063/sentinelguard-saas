/* Authorized Protocol Quality Assurance & Formal Verification Test Suite */

export type SubscriptionPlan = "FREE" | "PRO" | "ENTERPRISE";

export interface AccountSubscription {
  login: string;
  id: number;
  type: "User" | "Organization";
  plan: SubscriptionPlan;
  monthlyPriceInCents: number;
  status: "active" | "cancelled" | "pending";
  installedAt: string;
  updatedAt: string;
}

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";

export interface SecurityFinding {
  ruleId: string;
  category: "SECRET_LEAK" | "SOROBAN_INVARIANT" | "SOLIDITY_INVARIANT" | "CODE_SAFETY";
  severity: FindingSeverity;
  filePath: string;
  lineNumber?: number;
  snippet?: string;
  message: string;
  remediation: string;
}

export interface AuditResult {
  repository: string;
  prNumber: number;
  plan: SubscriptionPlan;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  findings: SecurityFinding[];
  passed: boolean;
  summary: string;
}

export interface MarketplaceWebhookPayload {
  action: "purchased" | "changed" | "cancelled" | "pending_change";
  effective_date: string;
  sender: {
    login: string;
    id: number;
  };
  marketplace_purchase: {
    account: {
      type: "User" | "Organization";
      id: number;
      login: string;
    };
    billing_cycle: "monthly" | "yearly";
    unit_count: number;
    plan: {
      id: number;
      name: string;
      description: string;
      monthly_price_in_cents: number;
      yearly_price_in_cents: number;
      price_model: "flat-rate" | "per-unit";
    };
  };
}

export interface PullRequestWebhookPayload {
  action: "opened" | "synchronize" | "reopened";
  number: number;
  pull_request: {
    number: number;
    title: string;
    head: {
      sha: string;
      ref: string;
    };
    base: {
      ref: string;
    };
  };
  repository: {
    name: string;
    full_name: string;
    owner: {
      login: string;
    };
    private: boolean;
  };
  installation?: {
    id: number;
  };
}

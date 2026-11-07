/* Authorized Protocol Quality Assurance & Formal Verification Test Suite */

import { AccountSubscription, SubscriptionPlan } from "../types/index.js";

export class SubscriptionStore {
  private accounts: Map<string, AccountSubscription> = new Map();
  private scanCounts: Map<string, number> = new Map();

  constructor() {
    // Seed default demo free accounts if needed
  }

  public getAccount(login: string): AccountSubscription {
    const existing = this.accounts.get(login.toLowerCase());
    if (existing) {
      return existing;
    }
    // Default tier is FREE
    const defaultSub: AccountSubscription = {
      login: login.toLowerCase(),
      id: 0,
      type: "User",
      plan: "FREE",
      monthlyPriceInCents: 0,
      status: "active",
      installedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.accounts.set(login.toLowerCase(), defaultSub);
    return defaultSub;
  }

  public setSubscription(
    login: string,
    id: number,
    type: "User" | "Organization",
    plan: SubscriptionPlan,
    monthlyPriceInCents: number,
    status: "active" | "cancelled" | "pending"
  ): AccountSubscription {
    const existing = this.accounts.get(login.toLowerCase());
    const sub: AccountSubscription = {
      login: login.toLowerCase(),
      id,
      type,
      plan,
      monthlyPriceInCents,
      status,
      installedAt: existing ? existing.installedAt : new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.accounts.set(login.toLowerCase(), sub);
    return sub;
  }

  public recordScan(repoFullName: string): number {
    const current = this.scanCounts.get(repoFullName) || 0;
    const next = current + 1;
    this.scanCounts.set(repoFullName, next);
    return next;
  }

  public getTotalScans(): number {
    let sum = 0;
    for (const count of this.scanCounts.values()) {
      sum += count;
    }
    return sum;
  }

  public getFinancialMetrics(): {
    activeSubscribers: number;
    totalMRRInCents: number;
    grossMRR: number;
    githubFee5Percent: number;
    netPayoutUSD: number;
  } {
    let totalMRRInCents = 0;
    let activeSubscribers = 0;

    for (const sub of this.accounts.values()) {
      if (sub.status === "active" && sub.plan !== "FREE") {
        totalMRRInCents += sub.monthlyPriceInCents;
        activeSubscribers += 1;
      }
    }

    const grossMRR = totalMRRInCents / 100;
    const githubFee5Percent = grossMRR * 0.05;
    const netPayoutUSD = grossMRR - githubFee5Percent;

    return {
      activeSubscribers,
      totalMRRInCents,
      grossMRR,
      githubFee5Percent,
      netPayoutUSD,
    };
  }

  public clear(): void {
    this.accounts.clear();
    this.scanCounts.clear();
  }
}

export const globalStore = new SubscriptionStore();

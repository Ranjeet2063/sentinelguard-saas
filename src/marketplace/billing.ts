/* Authorized Protocol Quality Assurance & Formal Verification Test Suite */

import { SubscriptionStore } from "../db/store.js";
import { MarketplaceWebhookPayload, SubscriptionPlan } from "../types/index.js";

export class MarketplaceBillingManager {
  private store: SubscriptionStore;

  constructor(store: SubscriptionStore) {
    this.store = store;
  }

  public handleMarketplaceEvent(payload: MarketplaceWebhookPayload): {
    success: boolean;
    login: string;
    action: string;
    plan: SubscriptionPlan;
    monthlyPriceUSD: number;
    message: string;
  } {
    const { action, marketplace_purchase } = payload;
    const account = marketplace_purchase.account;
    const planRaw = marketplace_purchase.plan.name.toUpperCase();
    const monthlyPriceInCents = marketplace_purchase.plan.monthly_price_in_cents;

    let targetPlan: SubscriptionPlan = "FREE";
    if (planRaw.includes("PRO")) {
      targetPlan = "PRO";
    } else if (planRaw.includes("ENTERPRISE") || planRaw.includes("TEAM")) {
      targetPlan = "ENTERPRISE";
    }

    if (action === "purchased") {
      this.store.setSubscription(
        account.login,
        account.id,
        account.type,
        targetPlan,
        monthlyPriceInCents,
        "active"
      );
      return {
        success: true,
        login: account.login,
        action,
        plan: targetPlan,
        monthlyPriceUSD: monthlyPriceInCents / 100,
        message: `Subscription activated for ${account.login} on ${targetPlan} plan ($${monthlyPriceInCents / 100}/mo).`,
      };
    }

    if (action === "changed") {
      this.store.setSubscription(
        account.login,
        account.id,
        account.type,
        targetPlan,
        monthlyPriceInCents,
        "active"
      );
      return {
        success: true,
        login: account.login,
        action,
        plan: targetPlan,
        monthlyPriceUSD: monthlyPriceInCents / 100,
        message: `Subscription changed for ${account.login} to ${targetPlan} plan ($${monthlyPriceInCents / 100}/mo).`,
      };
    }

    if (action === "cancelled") {
      this.store.setSubscription(
        account.login,
        account.id,
        account.type,
        "FREE",
        0,
        "cancelled"
      );
      return {
        success: true,
        login: account.login,
        action,
        plan: "FREE",
        monthlyPriceUSD: 0,
        message: `Subscription cancelled for ${account.login}. Reverted to FREE tier.`,
      };
    }

    return {
      success: true,
      login: account.login,
      action,
      plan: targetPlan,
      monthlyPriceUSD: monthlyPriceInCents / 100,
      message: `Pending change acknowledged for ${account.login}.`,
    };
  }
}

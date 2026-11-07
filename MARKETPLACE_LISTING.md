# 🛒 GitHub Marketplace Submission & Listing Package

## App Information
- **Name**: SentinelGuard - Smart Contract & PR Security Auditor
- **Short Description**: Autonomous security invariant scanner & automated code review auditor for Soroban smart contracts, Web3 protocols, and critical codebases.
- **Category**: Code quality, Security, Continuous integration

---

## 🎯 Value Proposition
SentinelGuard inspects every incoming Pull Request in sub-seconds before it can be merged into production:
1. **Secret Leak Prevention**: Instant detection of Stellar secret keys, EVM private keys, AWS credentials, and GitHub PATs.
2. **Soroban Smart Contract Invariants**: Enforces `require_auth()` checks, detects risky `.unwrap()` panics, and flags state mutation edge-cases.
3. **Automated Line-by-Line Review**: Posts clean, actionable GitHub PR review comments directly pointing to line numbers with one-click fixes.
4. **Zero Configuration**: Works automatically out-of-the-box upon repository installation.

---

## 💵 Marketplace Pricing Tiers

### Plan 1: Free Community Plan ($0 / month)
- Target: Open Source Repositories & Individual Builders
- Features:
  * Secret leak scanning (Stellar, EVM, AWS, GitHub)
  * Basic PR check run status
  * Unlimited public repositories

### Plan 2: Pro Plan ($29 / month)
- Target: Fast-moving Startups & Private Repositories
- Features:
  * Deep Soroban & Solidity invariant verification
  * Automated inline PR comments with suggested remediations
  * Unlimited private repositories for 1 organization
  * Sub-second scan latency

### Plan 3: Enterprise Plan ($99 / month)
- Target: DeFi Protocols, Financial Institutions & High-Assurance Teams
- Features:
  * Formal invariant verification reports
  * Fail-fast merge protection (blocks PR merge if critical invariant fails)
  * Priority webhook processing queue
  * Dedicated Slack/Discord alert webhooks

---

## 🔒 Security & Privacy Policy (Required by GitHub)
1. **Data Retention**: SentinelGuard does not store your private repository source code. Code diffs are analyzed in-memory during webhook execution and discarded immediately after check status creation.
2. **Access Control**: Operates strictly via short-lived GitHub App Installation Access Tokens generated with asymmetric RSA keys.
3. **Zero Telemetry Leaks**: Customer code and findings are never transmitted to third-party tracking services.

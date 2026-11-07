/* Authorized Protocol Quality Assurance & Formal Verification Test Suite */

import { AuditResult, FindingSeverity, SecurityFinding, SubscriptionPlan } from "../types/index.js";

export interface FileChange {
  filename: string;
  patch: string; // The git diff patch lines
}

export class SecurityInvariantScanner {
  /**
   * Scans an array of changed files from a Pull Request
   */
  public scanPullRequest(
    repository: string,
    prNumber: number,
    plan: SubscriptionPlan,
    changedFiles: FileChange[]
  ): AuditResult {
    const findings: SecurityFinding[] = [];

    for (const file of changedFiles) {
      // 1. Secret Leak Detection (Available to ALL plans, including FREE)
      this.scanSecrets(file, findings);

      // 2. Deep Invariant Checks (PRO & ENTERPRISE only)
      if (plan === "PRO" || plan === "ENTERPRISE") {
        if (file.filename.endsWith(".rs")) {
          this.scanSorobanRustInvariants(file, findings);
        } else if (file.filename.endsWith(".sol")) {
          this.scanSolidityInvariants(file, findings);
        } else if (file.filename.endsWith(".ts") || file.filename.endsWith(".js") || file.filename.endsWith(".py")) {
          this.scanWeb2Security(file, findings);
        }
      }
    }

    const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
    const highCount = findings.filter((f) => f.severity === "HIGH").length;
    const passed = criticalCount === 0 && highCount === 0;

    const summary = passed
      ? `✅ **SentinelGuard Audit Passed**: Checked ${changedFiles.length} file(s). Zero critical security invariant violations.`
      : `⚠️ **SentinelGuard Security Alert**: Found ${criticalCount} CRITICAL and ${highCount} HIGH severity issues. Resolve before merging!`;

    return {
      repository,
      prNumber,
      plan,
      totalFindings: findings.length,
      criticalCount,
      highCount,
      findings,
      passed,
      summary,
    };
  }

  private scanSecrets(file: FileChange, findings: SecurityFinding[]): void {
    const lines = file.patch.split("\n");

    lines.forEach((line, index) => {
      // Only scan added lines
      if (!line.startsWith("+") || line.startsWith("+++")) {
        return;
      }

      // Stellar Secret Key (56 chars starting with S)
      if (/S[A-Z0-9]{55}/.test(line)) {
        findings.push({
          ruleId: "SEC-001",
          category: "SECRET_LEAK",
          severity: "CRITICAL",
          filePath: file.filename,
          lineNumber: index + 1,
          snippet: line.trim(),
          message: "Potential Stellar Secret Key (ed25519) exposed in commit.",
          remediation: "Revoke key immediately and move secret to environment variables.",
        });
      }

      // Generic Private Key
      if (/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(line)) {
        findings.push({
          ruleId: "SEC-002",
          category: "SECRET_LEAK",
          severity: "CRITICAL",
          filePath: file.filename,
          lineNumber: index + 1,
          snippet: line.trim(),
          message: "Private key certificate embedded directly in source code.",
          remediation: "Remove certificate from git history and inject via secret manager.",
        });
      }

      // GitHub Token
      if (/ghp_[A-Za-z0-9_]{36}/.test(line)) {
        findings.push({
          ruleId: "SEC-003",
          category: "SECRET_LEAK",
          severity: "CRITICAL",
          filePath: file.filename,
          lineNumber: index + 1,
          snippet: line.trim(),
          message: "GitHub Personal Access Token (PAT) exposed in source code.",
          remediation: "Revoke token immediately in GitHub developer settings.",
        });
      }
    });
  }

  private scanSorobanRustInvariants(file: FileChange, findings: SecurityFinding[]): void {
    const lines = file.patch.split("\n");

    lines.forEach((line, index) => {
      if (!line.startsWith("+") || line.startsWith("+++")) {
        return;
      }

      // Check for dangerous unwrap in smart contracts
      if (/\.unwrap\(\)/.test(line) && !line.includes("// safe-unwrap")) {
        findings.push({
          ruleId: "SOR-001",
          category: "SOROBAN_INVARIANT",
          severity: "HIGH",
          filePath: file.filename,
          lineNumber: index + 1,
          snippet: line.trim(),
          message: "Explicit `.unwrap()` detected in Soroban contract. Can cause transaction panic and state revert.",
          remediation: "Return a custom contract `Result<T, ContractError>` instead of panicking.",
        });
      }

      // Check for state modification without require_auth check indicator
      if (/env\.storage\(\)\.(instance|persistent)\(\)\.set\(/.test(line)) {
        // Look up previous lines in patch for require_auth
        const patchContext = file.patch;
        if (!patchContext.includes("require_auth")) {
          findings.push({
            ruleId: "SOR-002",
            category: "SOROBAN_INVARIANT",
            severity: "HIGH",
            filePath: file.filename,
            lineNumber: index + 1,
            snippet: line.trim(),
            message: "State storage mutation without nearby `require_auth()` invocation.",
            remediation: "Verify caller authority before mutating persistent contract storage.",
          });
        }
      }
    });
  }

  private scanSolidityInvariants(file: FileChange, findings: SecurityFinding[]): void {
    const lines = file.patch.split("\n");

    lines.forEach((line, index) => {
      if (!line.startsWith("+") || line.startsWith("+++")) {
        return;
      }

      if (/tx\.origin/.test(line)) {
        findings.push({
          ruleId: "SOL-001",
          category: "SOLIDITY_INVARIANT",
          severity: "HIGH",
          filePath: file.filename,
          lineNumber: index + 1,
          snippet: line.trim(),
          message: "Use of `tx.origin` for authentication is vulnerable to phishing attacks.",
          remediation: "Replace `tx.origin` with `msg.sender`.",
        });
      }
    });
  }

  private scanWeb2Security(file: FileChange, findings: SecurityFinding[]): void {
    const lines = file.patch.split("\n");

    lines.forEach((line, index) => {
      if (!line.startsWith("+") || line.startsWith("+++")) {
        return;
      }

      // Hardcoded plaintext password assignments
      if (/(?:password|passwd|api_secret)\s*=\s*['"][^'"]{6,}['"]/i.test(line)) {
        findings.push({
          ruleId: "WEB-001",
          category: "CODE_SAFETY",
          severity: "HIGH",
          filePath: file.filename,
          lineNumber: index + 1,
          snippet: line.trim(),
          message: "Hardcoded credential or API secret string detected.",
          remediation: "Use environment variables (`process.env.VAR`) instead of literals.",
        });
      }
    });
  }
}

export const globalScanner = new SecurityInvariantScanner();

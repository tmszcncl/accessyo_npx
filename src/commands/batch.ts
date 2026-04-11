import chalk from 'chalk';
import ora from 'ora';
import { checkDns } from '../checks/dns.js';
import { checkTcp } from '../checks/tcp.js';
import { checkTls } from '../checks/tls.js';
import { checkHttp } from '../checks/http.js';
import { diagnoseHost } from './diagnose.js';
import { buildJsonOutput } from './json-output.js';

interface BatchResult {
  host: string;
  ok: boolean;
  failedAt?: string;
  warnings: string[];
}

async function checkOne(host: string, timeoutMs = 5000): Promise<BatchResult> {
  const dns = await checkDns(host, timeoutMs);
  if (!dns.ok) return { host, ok: false, failedAt: 'DNS', warnings: [] };

  const tcp = await checkTcp(host, 443, timeoutMs);
  if (!tcp.ok) return { host, ok: false, failedAt: 'TCP', warnings: [] };

  const tls = await checkTls(host, 443, timeoutMs);
  if (!tls.ok) return { host, ok: false, failedAt: 'TLS', warnings: [] };

  const http = await checkHttp(host, dns.aRecords, dns.aaaaRecords, timeoutMs);
  if (!http.ok) {
    const code = http.statusCode !== undefined ? ` ${http.statusCode}` : '';
    return { host, ok: false, failedAt: `HTTP${code}`, warnings: [] };
  }

  const warnings: string[] = [];

  if (!http.hsts) {
    warnings.push('HSTS');
  } else if (http.hsts.maxAge < 180 * 86400) {
    const days = Math.floor(http.hsts.maxAge / 86400);
    warnings.push(`HSTS short (${days}d)`);
  }

  if (tls.certDaysRemaining !== undefined && tls.certDaysRemaining < 30) {
    warnings.push(`cert ${tls.certDaysRemaining}d`);
  }

  if (http.ipv6 !== undefined && !http.ipv6.ok && http.ipv6.error !== 'timeout') {
    warnings.push('IPv6');
  }

  if (http.durationMs > 2000) {
    warnings.push(`slow ${http.durationMs}ms`);
  }

  return { host, ok: true, warnings };
}

export async function batch(hosts: string[], timeoutMs = 5000, json = false): Promise<void> {
  if (json) {
    const results = await Promise.all(
      hosts.map(async (host) => {
        const dns = await checkDns(host, timeoutMs);
        const tcp = dns.ok ? await checkTcp(host, 443, timeoutMs) : null;
        const tls = tcp?.ok ? await checkTls(host, 443, timeoutMs) : null;
        const http =
          (tls?.ok ?? tcp?.ok)
            ? await checkHttp(host, dns.aRecords, dns.aaaaRecords, timeoutMs)
            : null;
        return buildJsonOutput(host, dns, tcp, tls, http);
      }),
    );
    console.log(JSON.stringify(results, null, 2));
    return;
  }
  console.log();

  const maxLen = Math.max(...hosts.map((h) => h.length));
  // isTTY is undefined in non-TTY environments (pipes, CI)
  const isTTY = (process.stdout as { isTTY?: boolean }).isTTY === true;

  const resultText = (r: BatchResult): string => {
    const status = r.ok
      ? chalk.green('✓ WORKING')
      : chalk.red('✗ NOT WORKING') + (r.failedAt ? chalk.dim(` (${r.failedAt})`) : '');
    const warns =
      r.warnings.length > 0 ? '  ' + r.warnings.map((w) => chalk.yellow(`⚠ ${w}`)).join(' ') : '';
    return status + warns;
  };

  let results: BatchResult[];

  if (isTTY) {
    // Print all rows upfront with a placeholder
    for (const host of hosts) {
      process.stdout.write(`  ${host.padEnd(maxLen + 3)}${chalk.dim('· · ·')}\n`);
    }

    // Update a specific row in-place using ANSI cursor movement
    const updateRow = (index: number, text: string): void => {
      const up = hosts.length - index;
      const label = hosts.at(index) ?? '';
      process.stdout.write(`\x1b[${up}A\r\x1b[2K  ${label.padEnd(maxLen + 3)}${text}\x1b[${up}B\r`);
    };

    results = await Promise.all(
      hosts.map(async (host, i) => {
        const result = await checkOne(host, timeoutMs);
        updateRow(i, resultText(result));
        return result;
      }),
    );
  } else {
    // Non-TTY (CI / pipes): single spinner, print table after all done
    const spinner = ora(`Checking ${hosts.length} domains...`).start();
    results = await Promise.all(hosts.map((host) => checkOne(host, timeoutMs)));
    spinner.stop();

    for (const [i, r] of results.entries()) {
      const label = hosts.at(i) ?? '';
      console.log(`  ${label.padEnd(maxLen + 3)}${resultText(r)}`);
    }
  }

  const line = chalk.dim('─'.repeat(40));
  console.log();
  console.log(line);
  console.log();

  const working = results.filter((r) => r.ok).length;
  const failing = results.length - working;

  const workingText = working > 0 ? chalk.green(`${working} working`) : `${working} working`;
  const failingText = failing > 0 ? chalk.red(`${failing} failing`) : `${failing} failing`;
  console.log(`  ${workingText}, ${failingText}`);
  console.log();

  const failures = results.filter((r) => !r.ok);
  if (failures.length > 0) {
    const groups = new Map<string, BatchResult[]>();
    for (const r of failures) {
      const key = r.failedAt ?? 'unknown';
      const group = groups.get(key) ?? [];
      group.push(r);
      groups.set(key, group);
    }

    for (const group of groups.values()) {
      const groupHosts = group.map((r) => r.host);
      const [first] = group;
      if (first !== undefined) {
        await diagnoseHost(first.host, 443, groupHosts, timeoutMs);
      }
    }
  }
}

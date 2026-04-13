import chalk from 'chalk';
import ora from 'ora';
import { checkDns } from '../checks/dns.js';
import { checkTcp } from '../checks/tcp.js';
import { checkTls } from '../checks/tls.js';
import { checkHttp } from '../checks/http.js';
import { diagnoseHost } from './diagnose.js';
import { buildJsonOutput } from './json-output.js';
import { parseTarget } from '../target.js';

interface BatchResult {
  target: string;
  ok: boolean;
  failedAt?: string;
  warnings: string[];
}

async function checkOne(input: string, timeoutMs = 5000): Promise<BatchResult> {
  const parsed = parseTarget(input);
  const dns = await checkDns(parsed.host, timeoutMs);
  if (!dns.ok) return { target: parsed.normalizedTarget, ok: false, failedAt: 'DNS', warnings: [] };

  const tcp = await checkTcp(parsed.host, parsed.port, timeoutMs);
  if (!tcp.ok) return { target: parsed.normalizedTarget, ok: false, failedAt: 'TCP', warnings: [] };

  const tls = await checkTls(parsed.host, parsed.port, timeoutMs);
  if (!tls.ok) return { target: parsed.normalizedTarget, ok: false, failedAt: 'TLS', warnings: [] };

  const http = await checkHttp(parsed.httpTarget, parsed.host, dns.aRecords, dns.aaaaRecords, timeoutMs);
  if (!http.ok) {
    const code = http.statusCode !== undefined ? ` ${http.statusCode}` : '';
    return { target: parsed.normalizedTarget, ok: false, failedAt: `HTTP${code}`, warnings: [] };
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

  if (dns.resolverComparison?.splitHorizon) {
    warnings.push('split-horizon');
  }

  if (http.durationMs > 2000) {
    warnings.push(`slow ${http.durationMs}ms`);
  }

  return { target: parsed.normalizedTarget, ok: true, warnings };
}

export async function batch(
  hosts: string[],
  timeoutMs = 5000,
  json = false,
  debug = false,
): Promise<boolean> {
  if (json) {
    const results = await Promise.all(
      hosts.map(async (input) => {
        const parsed = parseTarget(input);
        const dns = await checkDns(parsed.host, timeoutMs);
        const tcp = dns.ok ? await checkTcp(parsed.host, parsed.port, timeoutMs) : null;
        const tls = tcp?.ok ? await checkTls(parsed.host, parsed.port, timeoutMs) : null;
        const http =
          (tls?.ok ?? tcp?.ok)
            ? await checkHttp(parsed.httpTarget, parsed.host, dns.aRecords, dns.aaaaRecords, timeoutMs)
            : null;
        return buildJsonOutput(parsed.normalizedTarget, dns, tcp, tls, http);
      }),
    );
    console.log(JSON.stringify(results, null, 2));
    return results.every((result) => result.summary.ok);
  }

  if (debug) {
    console.log();
    let allOk = true;
    const separator = chalk.dim('─'.repeat(40));
    for (const [index, host] of hosts.entries()) {
      if (index > 0) {
        console.log(separator);
        console.log();
      }
      const ok = await diagnoseHost(host, 443, undefined, timeoutMs, true);
      allOk = allOk && ok;
    }
    return allOk;
  }

  console.log();

  const labels = hosts.map((input) => parseTarget(input).normalizedTarget);
  const maxLen = Math.max(...labels.map((h) => h.length));
  // isTTY is undefined in non-TTY environments (pipes, CI)
  const isTTY = (process.stdout as { isTTY?: boolean }).isTTY === true;

  const resultText = (r: BatchResult): string => {
    const status = r.ok
      ? chalk.green('✓ WORKING')
      : chalk.red('✗ FAIL') + (r.failedAt ? chalk.dim(` (${r.failedAt})`) : '');
    const warns =
      r.warnings.length > 0 ? '  ' + r.warnings.map((w) => chalk.yellow(`⚠ ${w}`)).join(' ') : '';
    return status + warns;
  };

  let results: BatchResult[];

  if (isTTY) {
    // Print all rows upfront with a placeholder
    for (const label of labels) {
      process.stdout.write(`  ${label.padEnd(maxLen + 3)}${chalk.dim('· · ·')}\n`);
    }

    // Update a specific row in-place using ANSI cursor movement
    const updateRow = (index: number, text: string): void => {
      const up = hosts.length - index;
      const label = labels.at(index) ?? '';
      process.stdout.write(`\x1b[${up}A\r\x1b[2K  ${label.padEnd(maxLen + 3)}${text}\x1b[${up}B\r`);
    };

    results = await Promise.all(
      hosts.map(async (input, i) => {
        const result = await checkOne(input, timeoutMs);
        updateRow(i, resultText(result));
        return result;
      }),
    );
  } else {
    // Non-TTY (CI / pipes): single spinner, print table after all done
    const spinner = ora(`Checking ${hosts.length} domains...`).start();
    results = await Promise.all(hosts.map((input) => checkOne(input, timeoutMs)));
    spinner.stop();

    for (const [i, r] of results.entries()) {
      const label = labels.at(i) ?? '';
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

  return failing === 0;
}

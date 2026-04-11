import chalk from 'chalk';
import ora from 'ora';
import { checkDns } from '../checks/dns.js';
import { checkTcp } from '../checks/tcp.js';
import { checkTls } from '../checks/tls.js';
import { checkHttp } from '../checks/http.js';
import { diagnoseHost } from './diagnose.js';

interface BatchResult {
  host: string;
  ok: boolean;
  failedAt?: string;
}

async function checkOne(host: string): Promise<BatchResult> {
  const dns = await checkDns(host);
  if (!dns.ok) return { host, ok: false, failedAt: 'DNS' };

  const tcp = await checkTcp(host, 443);
  if (!tcp.ok) return { host, ok: false, failedAt: 'TCP' };

  const tls = await checkTls(host, 443);
  if (!tls.ok) return { host, ok: false, failedAt: 'TLS' };

  const http = await checkHttp(host, dns.aRecords, dns.aaaaRecords);
  if (!http.ok) {
    const code = http.statusCode !== undefined ? ` ${http.statusCode}` : '';
    return { host, ok: false, failedAt: `HTTP${code}` };
  }

  return { host, ok: true };
}

export async function batch(hosts: string[]): Promise<void> {
  console.log();

  const maxLen = Math.max(...hosts.map((h) => h.length));
  // isTTY is undefined in non-TTY environments (pipes, CI)
  const isTTY = (process.stdout as { isTTY?: boolean }).isTTY === true;

  const resultText = (r: BatchResult): string =>
    r.ok
      ? chalk.green('✓ WORKING')
      : chalk.red('✗ NOT WORKING') + (r.failedAt ? chalk.dim(` (${r.failedAt})`) : '');

  let results: BatchResult[];

  if (isTTY) {
    // Print all rows upfront with a placeholder
    for (const host of hosts) {
      process.stdout.write(`  ${host.padEnd(maxLen + 3)}${chalk.dim('· · ·')}\n`);
    }

    // Update a specific row in-place using ANSI cursor movement
    const updateRow = (index: number, text: string): void => {
      const up = hosts.length - index;
      process.stdout.write(
        `\x1b[${up}A\r\x1b[2K  ${hosts[index].padEnd(maxLen + 3)}${text}\x1b[${up}B\r`,
      );
    };

    results = await Promise.all(
      hosts.map(async (host, i) => {
        const result = await checkOne(host);
        updateRow(i, resultText(result));
        return result;
      }),
    );
  } else {
    // Non-TTY (CI / pipes): single spinner, print table after all done
    const spinner = ora(`Checking ${hosts.length} domains...`).start();
    results = await Promise.all(hosts.map((host) => checkOne(host)));
    spinner.stop();

    for (let i = 0; i < results.length; i++) {
      console.log(`  ${hosts[i].padEnd(maxLen + 3)}${resultText(results[i])}`);
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
      const hosts = group.map((r) => r.host);
      await diagnoseHost(group[0].host, 443, hosts);
    }
  }
}

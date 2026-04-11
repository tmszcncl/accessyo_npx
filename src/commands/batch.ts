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

  const results: BatchResult[] = [];

  for (const host of hosts) {
    const spinner = ora(host).start();
    const result = await checkOne(host);
    spinner.stop();
    results.push(result);
  }

  const maxLen = Math.max(...results.map((r) => r.host.length));

  for (const r of results) {
    const padded = r.host.padEnd(maxLen + 3);
    if (r.ok) {
      console.log(`  ${padded}${chalk.green('✓ WORKING')}`);
    } else {
      const reason = r.failedAt ? chalk.dim(` (${r.failedAt})`) : '';
      console.log(`  ${padded}${chalk.red('✗ NOT WORKING')}${reason}`);
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

import chalk from 'chalk';
import ora from 'ora';
import { checkDns } from '../checks/dns.js';
import { checkTcp } from '../checks/tcp.js';
import { checkTls } from '../checks/tls.js';
import { checkHttp } from '../checks/http.js';
import type { DnsResult, TcpResult, TlsResult, HttpResult } from '../types.js';

export async function diagnose(host: string, port = 443): Promise<void> {
  console.log();
  console.log(`  ${chalk.bold(host)}`);
  console.log();

  const spinner = ora('Running checks...').start();

  const [dns, tcp] = await Promise.all([checkDns(host), checkTcp(host, port)]);
  const tls = tcp.ok ? await checkTls(host, port) : null;
  const http = tls?.ok ?? tcp.ok ? await checkHttp(host) : null;

  spinner.stop();

  printDns(dns);
  console.log();
  printTcp(tcp);
  console.log();
  printTls(tls);
  console.log();
  printHttp(http);
  console.log();
}

function printDns(result: DnsResult): void {
  const duration = chalk.dim(`${result.durationMs}ms`);
  const resolver = chalk.dim(`resolver: ${result.resolver}`);

  if (!result.ok) {
    const code = result.errorCode ? ` (${result.errorCode})` : '';
    console.log(`  ${chalk.red('✗')}  DNS${code}  ${duration}`);
    console.log();
    console.log(`     ${chalk.red(result.error ?? 'Unknown error')}`);
    if (result.errorCode === 'TIMEOUT') {
      console.log(`     ${chalk.dim('→')} possible DNS blocking or slow resolver`);
    } else if (result.errorCode === 'NXDOMAIN') {
      console.log(`     ${chalk.dim('→')} check domain spelling`);
    }
    return;
  }

  console.log(`  ${chalk.green('✓')}  DNS  ${duration}  ${resolver}`);

  if (result.aRecords && result.aRecords.length > 0) {
    console.log(`     ${chalk.dim('A:')}    ${result.aRecords.join(', ')}`);
  }

  if (result.aaaaRecords && result.aaaaRecords.length > 0) {
    console.log(`     ${chalk.dim('AAAA:')} ${result.aaaaRecords.join(', ')}`);
  }

  if (!result.aRecords?.length && result.aaaaRecords?.length) {
    console.log(`     ${chalk.yellow('→')} IPv6 only — may fail on some networks`);
  } else {
    const ttl = result.ttl !== undefined ? `  TTL: ${result.ttl}s` : '';
    console.log(`     ${chalk.dim('→')} resolves correctly${ttl}`);
    if (result.cdn) {
      console.log(`     ${chalk.dim('→')} likely behind ${result.cdn} ${chalk.dim('(best-effort)')}`);
    }
  }
}

function printTcp(result: TcpResult): void {
  const duration = chalk.dim(`${result.durationMs}ms`);

  if (!result.ok) {
    console.log(`  ${chalk.red('✗')}  TCP  ${duration}  ${chalk.dim(`port ${result.port}`)}`);
    console.log();
    console.log(`     ${chalk.red(result.error ?? 'Unknown error')}`);
    console.log(`     ${chalk.dim('→')} TLS skipped (TCP failed)`);
    return;
  }

  console.log(`  ${chalk.green('✓')}  TCP  ${duration}  ${chalk.dim(`port ${result.port}`)}`);
}

function printTls(result: TlsResult | null): void {
  if (result === null) {
    console.log(`  ${chalk.dim('–')}  TLS  ${chalk.dim('skipped')}`);
    return;
  }

  const duration = chalk.dim(`${result.durationMs}ms`);

  if (!result.ok) {
    console.log(`  ${chalk.red('✗')}  TLS  ${duration}`);
    console.log();
    console.log(`     ${chalk.red(result.error ?? 'Unknown error')}`);
    return;
  }

  console.log(`  ${chalk.green('✓')}  TLS  ${duration}`);

  if (result.protocol) console.log(`     ${chalk.dim('protocol:')} ${result.protocol}`);
  if (result.cipher) console.log(`     ${chalk.dim('cipher:')}   ${result.cipher}`);

  if (result.certIssuer ?? result.certValidTo) {
    console.log(`     ${chalk.dim('cert:')}`);
    if (result.certIssuer) console.log(`       ${chalk.dim('issuer:')}   ${result.certIssuer}`);
    if (result.certValidTo) {
      const expiry = result.certExpired
        ? chalk.red(`${result.certValidTo} (EXPIRED)`)
        : result.certValidTo;
      console.log(`       ${chalk.dim('valid to:')} ${expiry}`);
    }
  }

  console.log(`     ${chalk.dim('→')} TLS handshake successful`);
}

function printHttp(result: HttpResult | null): void {
  if (result === null) {
    console.log(`  ${chalk.dim('–')}  HTTP  ${chalk.dim('skipped')}`);
    return;
  }

  const duration = chalk.dim(`${result.durationMs}ms`);

  if (!result.ok) {
    const block = result.blockedBy ? ` (${result.blockedBy})` : '';
    console.log(`  ${chalk.red('✗')}  HTTP${block}  ${duration}`);
    console.log();
    if (result.blockedBy) {
      console.log(`     ${chalk.red(`Request blocked by CDN / WAF`)}`);
    } else {
      console.log(`     ${chalk.red(result.error ?? `HTTP ${result.statusCode ?? 'error'}`)}`);
    }
    return;
  }

  console.log(`  ${chalk.green('✓')}  HTTP  ${duration}`);

  if (result.statusCode !== undefined) {
    console.log(`     ${chalk.dim('status:')} ${result.statusCode}`);
  }

  if (result.redirects.length > 0) {
    console.log(`     ${chalk.dim('redirects:')}`);
    for (const url of result.redirects) {
      console.log(`       ${chalk.dim(url)}`);
    }
    console.log(`       ${chalk.dim('→')} final`);
  }

  const headerEntries = Object.entries(result.headers);
  if (headerEntries.length > 0) {
    console.log(`     ${chalk.dim('headers:')}`);
    for (const [key, val] of headerEntries) {
      console.log(`       ${chalk.dim(key + ':')} ${val}`);
    }
  }

  const status = result.statusCode ?? 0;
  if (status >= 200 && status < 300) {
    console.log(`     ${chalk.dim('→')} HTTP OK`);
  } else if (status >= 400 && status < 500) {
    console.log(`     ${chalk.yellow('→')} client error — possible access restriction`);
  } else if (status >= 500) {
    console.log(`     ${chalk.red('→')} server error`);
  }
}

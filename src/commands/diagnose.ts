import chalk from 'chalk';
import ora from 'ora';
import { checkDns } from '../checks/dns.js';
import { checkTcp } from '../checks/tcp.js';
import { checkTls } from '../checks/tls.js';
import { checkHttp } from '../checks/http.js';
import { buildSummary } from '../summary.js';
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
  printSummary({ dns, tcp, tls, http });
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

function printSummary(input: Parameters<typeof buildSummary>[0]): void {
  const s = buildSummary(input);
  const line = chalk.dim('─'.repeat(40));

  const row = (label: string, ok: boolean | null, extra = '') => {
    const icon = ok === null ? chalk.dim('–') : ok ? chalk.green('✓') : chalk.red('✗');
    const text = ok === null ? chalk.dim('skipped') : ok ? chalk.green('OK') : chalk.red('FAIL');
    const suffix = extra ? chalk.dim(` (${extra})`) : '';
    console.log(`  ${label.padEnd(6)} ${icon} ${text}${suffix}`);
  };

  console.log(line);
  console.log();
  row('DNS', input.dns.ok);
  row('TCP', input.tcp.ok);
  row('TLS', input.tls === null ? null : input.tls.ok);
  row(
    'HTTP',
    input.http === null ? null : input.http.ok,
    input.http?.statusCode !== undefined ? String(input.http.statusCode) : undefined,
  );
  console.log();

  if (s.allOk) {
    console.log(`  ${chalk.green('STATUS:')} ${chalk.green('✓ WORKING')}`);
    console.log();
    console.log(`  ${chalk.dim('→')} all checks passed`);
  } else {
    console.log(`  ${chalk.red('STATUS:')} ${chalk.red('✗ NOT WORKING')}`);
    console.log();
    if (s.problem) {
      console.log(`  ${chalk.bold('Problem:')}`);
      console.log(`  ${chalk.dim('→')} ${s.problem}`);
      console.log();
    }
    if (s.likelyCause) {
      console.log(`  ${chalk.bold('Likely cause:')}`);
      console.log(`  ${chalk.dim('→')} ${s.likelyCause}`);
      console.log();
    }
    if (s.whatYouCanDo.length > 0) {
      console.log(`  ${chalk.bold('What you can do:')}`);
      for (const tip of s.whatYouCanDo) {
        console.log(`  ${chalk.dim('→')} ${tip}`);
      }
    }
  }

  console.log();
  console.log(line);
}

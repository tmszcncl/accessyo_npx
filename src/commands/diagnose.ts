import chalk from 'chalk';
import ora from 'ora';
import { checkDns } from '../checks/dns.js';
import { checkTcp } from '../checks/tcp.js';
import { checkTls } from '../checks/tls.js';
import { checkHttp } from '../checks/http.js';
import { getNetworkContext } from '../checks/network-context.js';
import { buildSummary } from '../summary.js';
import { buildJsonOutput } from './json-output.js';
import type { DnsResult, TcpResult, TlsResult, HttpResult, NetworkContext } from '../types.js';

export async function diagnose(
  host: string,
  port = 443,
  timeoutMs = 5000,
  json = false,
): Promise<boolean> {
  if (json) {
    const dns = await checkDns(host, timeoutMs);
    const tcp = dns.ok ? await checkTcp(host, port, timeoutMs) : null;
    const tls = tcp?.ok ? await checkTls(host, port, timeoutMs) : null;
    const http =
      (tls?.ok ?? tcp?.ok) ? await checkHttp(host, dns.aRecords, dns.aaaaRecords, timeoutMs) : null;
    const output = buildJsonOutput(host, dns, tcp, tls, http);
    console.log(JSON.stringify(output, null, 2));
    return output.summary.ok;
  }

  console.log();

  const spinner = ora('Detecting network...').start();
  const ctx = await getNetworkContext();
  spinner.stop();

  printNetworkContext(ctx);

  return diagnoseHost(host, port, undefined, timeoutMs);
}

export async function diagnoseHost(
  host: string,
  port = 443,
  displayHosts?: string[],
  timeoutMs = 5000,
): Promise<boolean> {
  const hideTiming = displayHosts !== undefined;
  let header: string;
  if (!displayHosts) {
    header = host;
  } else if (displayHosts.length <= 3) {
    header = displayHosts.join(', ');
  } else {
    header = displayHosts.slice(0, 3).join(', ') + chalk.dim(` (+${displayHosts.length - 3} more)`);
  }
  console.log(`  ${chalk.bold(header)}`);
  console.log();

  const spinner2 = ora('Running checks...').start();

  const dns = await checkDns(host, timeoutMs);
  const tcp = dns.ok ? await checkTcp(host, port, timeoutMs) : null;
  const tls = tcp?.ok ? await checkTls(host, port, timeoutMs) : null;
  const http =
    (tls?.ok ?? tcp?.ok) ? await checkHttp(host, dns.aRecords, dns.aaaaRecords, timeoutMs) : null;

  spinner2.stop();

  printDns(dns, hideTiming);
  console.log();
  printTcp(tcp, !dns.ok, hideTiming);
  console.log();
  printTls(tls, hideTiming);
  console.log();
  printHttp(http, hideTiming);
  console.log();
  printSummary({ dns, tcp, tls, http });
  console.log();

  return buildSummary({ dns, tcp, tls, http }).allOk;
}

function printNetworkContext(ctx: NetworkContext): void {
  const line = chalk.dim('─'.repeat(40));
  console.log(`  ${chalk.bold('Your network:')}`);
  console.log();

  const ip = ctx.publicIp ?? 'unknown';
  const country = ctx.country ? chalk.dim(` (${ctx.country})`) : '';
  console.log(`     ${chalk.dim('IP:')}    ${ip}${country}`);

  const resolverLabel = ctx.resolverLabel ? chalk.dim(` (${ctx.resolverLabel})`) : '';
  console.log(`     ${chalk.dim('DNS:')}   ${ctx.resolverIp}${resolverLabel}`);

  console.log();
  console.log(line);
  console.log();
}

function printDns(result: DnsResult, hideTiming = false): void {
  const duration = hideTiming ? '' : ` ${chalk.dim(`${result.durationMs}ms`)}`;

  if (!result.ok) {
    const code = result.errorCode ? ` (${result.errorCode})` : '';
    console.log(`  ${chalk.red('✗')}  DNS${code}${duration}`);
    console.log();
    console.log(`     ${chalk.red(result.error ?? 'Unknown error')}`);
    if (result.errorCode === 'TIMEOUT') {
      console.log(`     ${chalk.dim('→')} possible DNS blocking or slow resolver`);
    } else if (result.errorCode === 'NXDOMAIN') {
      console.log(`     ${chalk.dim('→')} check domain spelling`);
    }
    return;
  }

  console.log(
    `  ${chalk.green('✓')}  DNS${duration}  ${chalk.dim(`(resolver: ${result.resolver})`)}`,
  );

  if (result.aRecords && result.aRecords.length > 0) {
    console.log(`     ${chalk.dim('A:')}    ${result.aRecords.join(', ')}`);
  }

  if (result.aaaaRecords && result.aaaaRecords.length > 0) {
    console.log(`     ${chalk.dim('AAAA:')} ${result.aaaaRecords.join(', ')}`);
  }

  if (result.cname) {
    console.log(`     ${chalk.dim('CNAME:')} ${result.cname}`);
  }

  if (result.resolverComparison) {
    const { publicIps, splitHorizon } = result.resolverComparison;
    const sameIps =
      publicIps.length === (result.aRecords?.length ?? 0) &&
      publicIps.every((ip) => result.aRecords?.includes(ip));
    if (!sameIps) {
      const ipsText = publicIps.length > 0 ? publicIps.join(', ') : chalk.dim('(no response)');
      console.log(`     ${chalk.dim('1.1.1.1:')} ${ipsText}`);
    }
    if (splitHorizon) {
      console.log(
        `     ${chalk.yellow('→')} ${chalk.yellow('split-horizon DNS detected (system DNS returns private IP)')}`,
      );
    }
  }

  if (!result.aRecords?.length && result.aaaaRecords?.length) {
    console.log(`     ${chalk.yellow('→')} IPv6 only — may fail on some networks`);
  } else {
    if (result.ttl !== undefined) {
      console.log(`     ${chalk.dim('TTL:')}  ${result.ttl}s`);
    }
    console.log(`     ${chalk.dim('→')} resolves correctly`);
  }
}

function printTcp(result: TcpResult | null, dnsFailed = false, hideTiming = false): void {
  if (result === null) {
    const reason = dnsFailed ? chalk.dim(' (DNS failed)') : '';
    console.log(`  ${chalk.dim('–')}  TCP  ${chalk.dim('skipped')}${reason}`);
    return;
  }

  const duration = hideTiming ? '' : ` ${chalk.dim(`${result.durationMs}ms`)}`;

  if (!result.ok) {
    console.log(`  ${chalk.red('✗')}  TCP${duration}  ${chalk.dim(`(port ${result.port})`)}`);
    console.log();
    console.log(`     ${chalk.red(result.error ?? 'Unknown error')}`);
    console.log(`     ${chalk.dim('→')} TLS skipped (TCP failed)`);
    return;
  }

  console.log(`  ${chalk.green('✓')}  TCP${duration}  ${chalk.dim(`(port ${result.port})}`)}`);
}

function printTls(result: TlsResult | null, hideTiming = false): void {
  if (result === null) {
    console.log(`  ${chalk.dim('–')}  TLS  ${chalk.dim('skipped')}`);
    return;
  }

  const duration = hideTiming ? '' : ` ${chalk.dim(`${result.durationMs}ms`)}`;

  if (!result.ok) {
    console.log(`  ${chalk.red('✗')}  TLS${duration}`);
    console.log();
    console.log(`     ${chalk.red(result.error ?? 'Unknown error')}`);
    return;
  }

  console.log(`  ${chalk.green('✓')}  TLS${duration}`);

  if (result.protocol) console.log(`     ${chalk.dim('protocol:')} ${result.protocol}`);
  if (result.cipher) console.log(`     ${chalk.dim('cipher:')}   ${result.cipher}`);
  if (result.alpnProtocol) {
    const h2 = result.alpnProtocol === 'h2';
    const label = h2 ? chalk.green('HTTP/2') : chalk.dim('HTTP/1.1');
    console.log(`     ${chalk.dim('ALPN:')}    ${label}`);
  }

  if (result.certIssuer ?? result.certValidTo) {
    console.log(`     ${chalk.dim('cert:')}`);
    if (result.certIssuer) console.log(`       ${chalk.dim('issuer:')}   ${result.certIssuer}`);
    if (result.certValidTo) {
      const expiry = result.certExpired
        ? chalk.red(`${result.certValidTo} (EXPIRED)`)
        : result.certValidTo;
      console.log(`       ${chalk.dim('valid to:')} ${expiry}`);
    }
    if (result.hostnameMatch !== undefined) {
      const label = result.hostnameMatch ? chalk.green('✓ OK') : chalk.red('✗ mismatch');
      console.log(`       ${chalk.dim('hostname:')} ${label}`);
    }
  }

  console.log(`     ${chalk.dim('→')} TLS handshake successful`);

  if (result.certExpired) {
    console.log(`     ${chalk.red('→')} certificate expired`);
  } else if (result.certDaysRemaining !== undefined && result.certDaysRemaining < 14) {
    console.log(
      `     ${chalk.yellow('→')} certificate expiring soon (~${result.certDaysRemaining} days remaining)`,
    );
  } else if (result.certDaysRemaining !== undefined) {
    console.log(
      `     ${chalk.dim('→')} certificate valid (~${result.certDaysRemaining} days remaining)`,
    );
  }
}

function statusLabel(code: number): string {
  if (code === 200) return 'OK';
  if (code === 201) return 'Created';
  if (code === 301) return 'Moved Permanently';
  if (code === 302) return 'Found (Redirect)';
  if (code === 400) return 'Bad Request';
  if (code === 401) return 'Unauthorized';
  if (code === 403) return 'Forbidden';
  if (code === 404) return 'Not Found';
  if (code === 429) return 'Too Many Requests';
  if (code === 500) return 'Server Error';
  if (code === 502) return 'Bad Gateway';
  if (code === 503) return 'Service Unavailable';
  return '';
}

function redirectStepLabel(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    const path = `${parsed.pathname}${parsed.search}`;
    return `${parsed.protocol}//${parsed.host}${path}`;
  } catch {
    return rawUrl;
  }
}

function printHttp(result: HttpResult | null, hideTiming = false): void {
  if (result === null) {
    console.log(`  ${chalk.dim('–')}  HTTP  ${chalk.dim('skipped')}`);
    return;
  }

  const duration = hideTiming ? '' : ` ${chalk.dim(`${result.durationMs}ms`)}`;

  if (!result.ok) {
    const block = result.blockedBy ? ` (${result.blockedBy})` : '';
    console.log(`  ${chalk.red('✗')}  HTTP${block}${duration}`);
    console.log();
    if (result.blockedBy === 'Cloudflare') {
      console.log(`     ${chalk.red('Request blocked by Cloudflare / WAF')}`);
    } else if (result.blockedBy === 'server-side') {
      console.log(`     ${chalk.red('Request blocked (server-side 403)')}`);
    } else {
      console.log(`     ${chalk.red(result.error ?? `HTTP ${result.statusCode ?? 'error'}`)}`);
    }
    return;
  }

  console.log(`  ${chalk.green('✓')}  HTTP${duration}`);

  if (result.statusCode !== undefined) {
    console.log(
      `     ${chalk.dim('status:')} ${result.statusCode} ${statusLabel(result.statusCode)}`,
    );
  }

  if (result.ttfb !== undefined) {
    console.log(`     ${chalk.dim('TTFB:')}   ${result.ttfb}ms`);
  }

  if (result.redirects.length > 0) {
    console.log(`     ${chalk.dim('redirects:')}`);
    const labels = result.redirects.map(redirectStepLabel);
    const chain = labels.join(chalk.dim(' -> '));
    console.log(`       ${chalk.dim('chain:')} ${chain}`);
  } else {
    console.log(`     ${chalk.dim('(no redirects)')}`);
  }

  const headerEntries = Object.entries(result.headers).filter(
    ([key]) => key !== 'strict-transport-security',
  );
  if (headerEntries.length > 0) {
    console.log(`     ${chalk.dim('headers:')}`);
    for (const [key, val] of headerEntries) {
      console.log(`       ${chalk.dim(key + ':')} ${val}`);
    }
  }

  if (result.hsts) {
    const days = Math.floor(result.hsts.maxAge / 86400);
    const ageLabel = days >= 1 ? `${days}d` : `${result.hsts.maxAge}s`;
    const tooShort = result.hsts.maxAge < 180 * 86400;
    const extrasStr =
      (result.hsts.includeSubDomains ? ' · includeSubDomains' : '') +
      (result.hsts.preload ? ' · preload' : '');
    if (tooShort) {
      console.log(
        `     ${chalk.dim('hsts:')}    ${chalk.yellow(`⚠ max-age ${ageLabel} — increase to ≥ 180d`)}`,
      );
    } else {
      console.log(
        `     ${chalk.dim('hsts:')}    ${chalk.green(`✓ max-age ${ageLabel}${extrasStr}`)}`,
      );
    }
  } else {
    console.log(
      `     ${chalk.dim('hsts:')}    ${chalk.yellow('✗ not set — site can be downgraded to HTTP')}`,
    );
  }

  if (result.ipv4 !== undefined || result.ipv6 !== undefined) {
    console.log(`     ${chalk.dim('IP connectivity:')}`);
    if (result.ipv4 !== undefined) {
      const timedOut = !result.ipv4.ok && result.ipv4.error === 'timeout';
      const icon = result.ipv4.ok ? chalk.green('✓') : timedOut ? chalk.dim('–') : chalk.red('✗');
      const text = result.ipv4.ok
        ? chalk.green('OK')
        : timedOut
          ? chalk.dim('timeout (CDN rate-limit?)')
          : chalk.red('FAIL');
      const ms = chalk.dim(`(${result.ipv4.durationMs}ms)`);
      console.log(`       ${chalk.dim('IPv4:')} ${icon} ${text} ${ms}`);
    }
    if (result.ipv6 !== undefined) {
      const timedOut = !result.ipv6.ok && result.ipv6.error === 'timeout';
      const icon = result.ipv6.ok ? chalk.green('✓') : timedOut ? chalk.dim('–') : chalk.red('✗');
      const text = result.ipv6.ok
        ? chalk.green('OK')
        : timedOut
          ? chalk.dim('timeout (CDN rate-limit?)')
          : chalk.red('FAIL');
      const ms = chalk.dim(`(${result.ipv6.durationMs}ms)`);
      console.log(`       ${chalk.dim('IPv6:')} ${icon} ${text} ${ms}`);
    }
  }

  const status = result.statusCode ?? 0;
  if (status >= 200 && status < 300) {
    console.log(`     ${chalk.dim('→')} HTTP OK`);
  } else if (status >= 300 && status < 400) {
    console.log(`     ${chalk.dim('→')} redirects detected`);
  } else if (status === 403 || status === 503) {
    console.log(`     ${chalk.yellow('→')} request blocked (possible CDN / WAF)`);
  } else if (status === 404) {
    console.log(`     ${chalk.yellow('→')} page not found`);
  } else if (status >= 500) {
    console.log(`     ${chalk.red('→')} server error`);
  } else if (status >= 400) {
    console.log(`     ${chalk.yellow('→')} client error — possible access restriction`);
  }

  if (result.cdn) {
    console.log(`     ${chalk.dim('→')} served via ${result.cdn} ${chalk.dim('(CDN edge)')}`);
  }

  if (result.ipv4?.ok && result.ipv6?.ok) {
    console.log(`     ${chalk.dim('→')} both IPv4 and IPv6 working`);
  } else if (result.ipv4?.ok && result.ipv6 !== undefined && !result.ipv6.ok) {
    console.log(`     ${chalk.yellow('→')} IPv6 connectivity issue (may affect some users)`);
  }

  if (result.browserDiffers === true) {
    console.log(
      `     ${chalk.yellow('→')} server responds differently to browsers (status: ${result.browserStatusCode ?? '?'} vs ${status})`,
    );
  }

  if (result.durationMs > 2000) {
    console.log(`     ${chalk.yellow('→')} slow response (${result.durationMs}ms)`);
  }

  if (result.wwwCheck) {
    const { kind } = result.wwwCheck;
    if (kind === 'apex→www') {
      console.log(`     ${chalk.dim('→')} redirects to www (canonical: www)`);
    } else if (kind === 'www→apex') {
      console.log(`     ${chalk.dim('→')} redirects to apex (canonical: non-www)`);
    } else if (kind === 'both-ok') {
      console.log(
        `     ${chalk.yellow('→')} www and non-www both serve content (no canonical redirect)`,
      );
    } else if (kind === 'www-unreachable') {
      console.log(`     ${chalk.yellow('→')} www version unreachable — only one variant works`);
    }
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
  row('DNS', input.dns.ok, `${input.dns.durationMs}ms`);
  row(
    'TCP',
    input.tcp === null ? null : input.tcp.ok,
    input.tcp ? `${input.tcp.durationMs}ms` : '',
  );
  row(
    'TLS',
    input.tls === null ? null : input.tls.ok,
    input.tls ? `${input.tls.durationMs}ms` : '',
  );
  row(
    'HTTP',
    input.http === null ? null : input.http.ok,
    input.http
      ? `${input.http.statusCode !== undefined ? `${input.http.statusCode}, ` : ''}${input.http.durationMs}ms`
      : '',
  );

  const total =
    input.dns.durationMs +
    (input.tcp?.durationMs ?? 0) +
    (input.tls?.durationMs ?? 0) +
    (input.http?.durationMs ?? 0);
  console.log();
  console.log(`  ${'Total'.padEnd(6)} ${chalk.dim(`${total}ms`)}`);
  console.log();

  if (s.allOk) {
    console.log(`  ${chalk.green('STATUS:')} ${chalk.green('✓ WORKING')}`);
    console.log();
    console.log(`  ${chalk.dim('→')} all checks passed`);
  } else {
    console.log(`  ${chalk.red('STATUS:')} ${chalk.red('✗ NOT WORKING')}`);
    console.log();
    if (s.problem) {
      console.log(`  ${chalk.bold.red('ROOT CAUSE:')}`);
      console.log(`  ${chalk.red('→')} ${s.problem}`);
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

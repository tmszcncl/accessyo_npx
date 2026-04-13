import type { DnsResult, TcpResult, TlsResult, HttpResult } from '../types.js';
import { buildSummary } from '../summary.js';
import type { SummaryStatus, SummaryWarning } from '../summary.js';

export interface JsonOutput {
  host: string;
  timestamp: string;
  checks: {
    dns: DnsResult;
    tcp: TcpResult | null;
    tls: TlsResult | null;
    http: HttpResult | null;
  };
  summary: {
    ok: boolean;
    status: SummaryStatus;
    explanation: string;
    warnings: SummaryWarning[];
    problem: string | null;
    likelyCause: string | null;
    whatYouCanDo: string[];
    totalMs: number;
  };
}

export function buildJsonOutput(
  host: string,
  dns: DnsResult,
  tcp: TcpResult | null,
  tls: TlsResult | null,
  http: HttpResult | null,
): JsonOutput {
  const summary = buildSummary({ dns, tcp, tls, http });
  const totalMs =
    dns.durationMs + (tcp?.durationMs ?? 0) + (tls?.durationMs ?? 0) + (http?.durationMs ?? 0);

  return {
    host,
    timestamp: new Date().toISOString(),
    checks: { dns, tcp, tls, http },
    summary: {
      ok: summary.allOk,
      status: summary.status,
      explanation: summary.explanation,
      warnings: summary.warnings,
      problem: summary.problem,
      likelyCause: summary.likelyCause,
      whatYouCanDo: summary.whatYouCanDo,
      totalMs,
    },
  };
}

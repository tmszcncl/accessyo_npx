#!/usr/bin/env node
import { program } from 'commander';
import { diagnose } from './commands/diagnose.js';
import { batch } from './commands/batch.js';

program
  .name('accessyo')
  .description('See why your users cannot connect')
  .argument('<host...>', 'one or more hosts to diagnose')
  .option('--timeout <ms>', 'per-check timeout in milliseconds', '5000')
  .option('--json', 'output results as JSON')
  .action(async (hosts: string[], opts: { timeout: string; json?: boolean }) => {
    const timeoutMs = Math.max(500, parseInt(opts.timeout, 10) || 5000);
    const json = opts.json === true;
    const [first] = hosts;
    if (hosts.length === 1 && first !== undefined) {
      await diagnose(first, 443, timeoutMs, json);
    } else {
      await batch(hosts, timeoutMs, json);
    }
  });

program
  .command('diagnose <host>', { isDefault: false })
  .description('Diagnose connectivity to a host')
  .option('--timeout <ms>', 'per-check timeout in milliseconds', '5000')
  .option('--json', 'output results as JSON')
  .action(async (host: string, opts: { timeout: string; json?: boolean }) => {
    const timeoutMs = Math.max(500, parseInt(opts.timeout, 10) || 5000);
    await diagnose(host, 443, timeoutMs, opts.json === true);
  });

await program.parseAsync();

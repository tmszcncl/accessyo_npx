#!/usr/bin/env node
import { program } from 'commander';
import { diagnose } from './commands/diagnose.js';

program
  .name('accessyo')
  .description('See why your users cannot connect')
  .argument('<host>', 'host to diagnose')
  .action(async (host: string) => {
    await diagnose(host);
  });

program
  .command('diagnose <host>', { isDefault: false })
  .description('Diagnose connectivity to a host')
  .action(async (host: string) => {
    await diagnose(host);
  });

await program.parseAsync();

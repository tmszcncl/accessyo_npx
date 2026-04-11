#!/usr/bin/env node
import { program } from 'commander';
import { diagnose } from './commands/diagnose.js';
import { batch } from './commands/batch.js';

program
  .name('accessyo')
  .description('See why your users cannot connect')
  .argument('<host...>', 'one or more hosts to diagnose')
  .action(async (hosts: string[]) => {
    const [first] = hosts;
    if (hosts.length === 1 && first !== undefined) {
      await diagnose(first);
    } else {
      await batch(hosts);
    }
  });

program
  .command('diagnose <host>', { isDefault: false })
  .description('Diagnose connectivity to a host')
  .action(async (host: string) => {
    await diagnose(host);
  });

await program.parseAsync();

#!/usr/bin/env node

import { Command } from 'commander';
import { nodeCommand } from './commands/node';
import { keygenCommand } from './commands/keygen';
import { addressCommand } from './commands/address';
import { signCommand } from './commands/sign';

const program = new Command();

program
  .name('clirft')
  .description('Cloud MPC wallet — 2-of-3 threshold ECDSA, BIP32/44 HD addresses, Ethereum')
  .version('1.0.0');

program.addCommand(nodeCommand);
program.addCommand(keygenCommand);
program.addCommand(addressCommand);
program.addCommand(signCommand);

program.parse();

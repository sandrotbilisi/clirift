import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import { loadConfig } from '../../config/loader';
import { AddressIndex } from '../../wallet/AddressIndex';

export const addressCommand = new Command('address')
  .description('Derive Ethereum addresses from PK_master (no network required)')
  .option('--index <n>', 'Derive address at a single index', undefined)
  .option('--count <n>', 'Derive N addresses starting at index 0', undefined)
  .option('--data-dir <path>', 'Override CLIRFT_DATA_DIR')
  .action(async (options) => {
    if (options.dataDir) process.env.CLIRFT_DATA_DIR = options.dataDir;

    let config;
    try {
      config = loadConfig();
    } catch (err) {
      console.error(chalk.red('Configuration error:'), String(err));
      process.exit(1);
    }

    // Load ceremony.json to get pkMaster and chainCode
    const ceremonyPath = path.join(config.CLIRFT_DATA_DIR, 'keyshare', 'ceremony.json');
    if (!fs.existsSync(ceremonyPath)) {
      console.error(
        chalk.red('No ceremony.json found.'),
        'Run',
        chalk.yellow('clirft keygen'),
        'first.'
      );
      process.exit(1);
    }

    let ceremony: { pkMaster: string; chainCode: string };
    try {
      ceremony = JSON.parse(fs.readFileSync(ceremonyPath, 'utf8'));
    } catch {
      console.error(chalk.red('Failed to parse ceremony.json'));
      process.exit(1);
    }

    const index = options.index !== undefined ? parseInt(options.index, 10) : undefined;
    const count = options.count !== undefined ? parseInt(options.count, 10) : undefined;

    if (index === undefined && count === undefined) {
      // Default: show first address
      console.error(
        chalk.yellow('Usage: clirft address --index <n>  OR  --count <n>')
      );
      process.exit(1);
    }

    const addrIndex = new AddressIndex(
      config.CLIRFT_DATA_DIR,
      ceremony.pkMaster,
      ceremony.chainCode
    );

    console.log(chalk.cyan('\n  CLIRift Address Derivation'));
    console.log(chalk.gray('  PK_master: ') + chalk.yellow(ceremony.pkMaster));
    console.log(chalk.gray('  ─────────────────────────────────────────────────────────────────'));
    console.log(
      chalk.gray('  Index   Path                        Address')
    );
    console.log(
      chalk.gray('  ─────   ──────────────────────────  ──────────────────────────────────────────────')
    );

    if (index !== undefined) {
      const entry = addrIndex.deriveOne(index);
      console.log(
        `  ${String(index).padEnd(7)} ${entry.path.padEnd(26)}  ${chalk.green(entry.address)}`
      );
    } else if (count !== undefined) {
      const entries = addrIndex.deriveRange(count);
      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        console.log(
          `  ${String(i).padEnd(7)} ${entry.path.padEnd(26)}  ${chalk.green(entry.address)}`
        );
      }
    }

    console.log('');
  });

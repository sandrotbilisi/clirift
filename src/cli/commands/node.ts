import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig } from '../../config/loader';
import { NodeServer } from '../../core/NodeServer';

export const nodeCommand = new Command('node')
  .description('Start the CLIRift MPC node daemon')
  .option('--data-dir <path>', 'Override CLIRFT_DATA_DIR')
  .option('--log-level <level>', 'Override LOG_LEVEL (error|warn|info|debug)')
  .action(async (options) => {
    // Apply CLI overrides before loading config
    if (options.dataDir) process.env.CLIRFT_DATA_DIR = options.dataDir;
    if (options.logLevel) process.env.LOG_LEVEL = options.logLevel;

    let config;
    try {
      config = loadConfig();
    } catch (err) {
      console.error(chalk.red('Configuration error:'), String(err));
      process.exit(1);
    }

    console.log(chalk.cyan('\n  CLIRift MPC Node'));
    console.log(chalk.gray('  ─────────────────────────────────────────'));
    console.log(`  Node ID  : ${chalk.yellow(config.CLIRFT_NODE_ID)}`);
    console.log(`  Listen   : ${chalk.yellow(`${config.CLIRFT_LISTEN_HOST}:${config.CLIRFT_LISTEN_PORT}`)}`);
    console.log(`  Public   : ${chalk.yellow(config.CLIRFT_PUBLIC_URL)}`);
    console.log(`  Peers    : ${chalk.yellow(config.CLIRFT_PEERS.length)} configured`);
    console.log(`  Threshold: ${chalk.yellow(`${config.CLIRFT_THRESHOLD}-of-${config.CLIRFT_TOTAL_PARTIES}`)}`);
    console.log(`  Chain ID : ${chalk.yellow(config.CLIRFT_CHAIN_ID)}`);
    console.log(chalk.gray('  ─────────────────────────────────────────\n'));

    const server = new NodeServer(config);

    // Graceful shutdown
    const shutdown = async (signal: string) => {
      console.log(chalk.yellow(`\n  ${signal} received — shutting down...`));
      await server.stop();
      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));

    try {
      await server.start();
      console.log(chalk.green('  Node started. Press Ctrl+C to stop.\n'));
    } catch (err) {
      console.error(chalk.red('\n  Failed to start node:'), err);
      process.exit(1);
    }
  });

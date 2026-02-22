import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig } from '../../config/loader';
import { NodeServer } from '../../core/NodeServer';
import { DkgCoordinator } from '../../core/dkg/DkgCoordinator';
import { SigningCoordinator } from '../../core/signing/SigningCoordinator';
import { KeyShareStore } from '../../storage/KeyShareStore';
import { loadOrCreateNodeIdentity } from '../../network/security/NodeIdentity';
import { AddressIndex } from '../../wallet/AddressIndex';
import logger from '../../utils/logger';

export const nodeCommand = new Command('node')
  .description('Start the CLIRift MPC node daemon')
  .option('--data-dir <path>', 'Override CLIRFT_DATA_DIR')
  .option('--log-level <level>', 'Override LOG_LEVEL (error|warn|info|debug)')
  .action(async (options) => {
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

    // Load node identity (needed for Round 3 share decryption)
    const identity = loadOrCreateNodeIdentity(config.CLIRFT_DATA_DIR, config.CLIRFT_NODE_ID);

    const keyShareStore = new KeyShareStore(
      config.CLIRFT_DATA_DIR,
      config.CLIRFT_NODE_ID,
      config.CLIRFT_STORAGE_BACKEND,
      {
        kmsKeyId: config.CLIRFT_KMS_KEY_ID,
        localPassphrase: config.CLIRFT_LOCAL_PASSPHRASE,
      }
    );

    const server = new NodeServer(config);

    // ── DKG Coordinator (participant mode — responds to DKG_PROPOSE) ──────────
    const dkgCoordinator = new DkgCoordinator({
      nodeId: config.CLIRFT_NODE_ID,
      nodeServer: server,
      keyShareStore,
      myPrivateKeyPem: identity.keyPem,
      threshold: config.CLIRFT_THRESHOLD,
      totalParties: config.CLIRFT_TOTAL_PARTIES,
      timeoutMs: config.CLIRFT_DKG_TIMEOUT_MS,
    });

    dkgCoordinator.on('complete', (pkMaster, chainCode) => {
      console.log(chalk.green('\n  DKG ceremony complete!'));
      console.log(`  PK_master : ${chalk.yellow(pkMaster)}`);
      const addrIndex = new AddressIndex(config.CLIRFT_DATA_DIR, pkMaster, chainCode);
      const first = addrIndex.deriveOne(0);
      console.log(`  Address 0 : ${chalk.green(first.address)}\n`);
    });

    dkgCoordinator.on('aborted', (reason) => {
      logger.error(`[node] DKG ceremony aborted: ${reason}`);
    });

    // ── Signing Coordinator (participant mode) ────────────────────────────────
    const signingCoordinator = new SigningCoordinator({
      nodeId: config.CLIRFT_NODE_ID,
      nodeServer: server,
      keyShareStore,
      myPrivateKeyPem: identity.keyPem,
      timeoutMs: config.CLIRFT_SIGN_TIMEOUT_MS,
    });

    signingCoordinator.on('complete', (sig, _signedTxHex) => {
      logger.info(`[node] Signing complete: r=${sig.r} s=${sig.s} v=${sig.v}`);
    });

    signingCoordinator.on('aborted', (reason) => {
      logger.error(`[node] Signing aborted: ${reason}`);
    });

    // ── Wire messages from network → coordinators ─────────────────────────────
    server.on('dkgMessage', (nodeId, msg) => {
      dkgCoordinator.handleMessage(nodeId, msg as { type: any; payload: unknown });
    });

    server.on('signMessage', (nodeId, msg) => {
      signingCoordinator.handleMessage(nodeId, msg as { type: any; payload: unknown });
    });

    // ── Wire peer pubkeys → coordinators (for Round 3 encryption) ─────────────
    server.onPeerIdentified((nodeId, pubkeyPem) => {
      dkgCoordinator.setPeerPubkey(nodeId, pubkeyPem);
      signingCoordinator.setPeerPubkey(nodeId, pubkeyPem);
    });

    // ── Graceful shutdown ─────────────────────────────────────────────────────
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

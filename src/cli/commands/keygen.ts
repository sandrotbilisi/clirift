import { Command } from 'commander';
import chalk from 'chalk';
import path from 'path';
import { loadConfig } from '../../config/loader';
import { NodeServer } from '../../core/NodeServer';
import { DkgCoordinator } from '../../core/dkg/DkgCoordinator';
import { KeyShareStore } from '../../storage/KeyShareStore';
import { loadOrCreateNodeIdentity } from '../../network/security/NodeIdentity';
import { AddressIndex } from '../../wallet/AddressIndex';

export const keygenCommand = new Command('keygen')
  .description('Initiate a DKG ceremony to generate the distributed master key')
  .option('--data-dir <path>', 'Override CLIRFT_DATA_DIR')
  .option('--timeout <ms>', 'Override CLIRFT_DKG_TIMEOUT_MS')
  .action(async (options) => {
    if (options.dataDir) process.env.CLIRFT_DATA_DIR = options.dataDir;
    if (options.timeout) process.env.CLIRFT_DKG_TIMEOUT_MS = options.timeout;

    let config;
    try {
      config = loadConfig();
    } catch (err) {
      console.error(chalk.red('Configuration error:'), String(err));
      process.exit(1);
    }

    const keyShareStore = new KeyShareStore(
      config.CLIRFT_DATA_DIR,
      config.CLIRFT_NODE_ID,
      config.CLIRFT_STORAGE_BACKEND,
      {
        kmsKeyId: config.CLIRFT_KMS_KEY_ID,
        localPassphrase: config.CLIRFT_LOCAL_PASSPHRASE,
      }
    );

    if (keyShareStore.exists()) {
      console.error(
        chalk.red('\n  Key share already exists.'),
        'Delete',
        chalk.yellow(path.join(config.CLIRFT_DATA_DIR, 'keyshare', 'keyshare.enc')),
        'to run a new ceremony.'
      );
      process.exit(1);
    }

    // Load node identity
    const identity = loadOrCreateNodeIdentity(config.CLIRFT_DATA_DIR, config.CLIRFT_NODE_ID);

    // Start the node server
    const nodeServer = new NodeServer(config);
    await nodeServer.start();

    console.log(chalk.cyan('\n  CLIRift DKG Ceremony'));
    console.log(chalk.gray('  ─────────────────────────────────────────'));
    console.log(`  Node ID  : ${chalk.yellow(config.CLIRFT_NODE_ID)}`);
    console.log(`  Threshold: ${chalk.yellow(`${config.CLIRFT_THRESHOLD}-of-${config.CLIRFT_TOTAL_PARTIES}`)}`);
    console.log(`  Timeout  : ${chalk.yellow(`${config.CLIRFT_DKG_TIMEOUT_MS / 1000}s`)}`);
    console.log(chalk.gray('  ─────────────────────────────────────────'));
    console.log(chalk.gray('\n  Waiting for peers to connect...'));

    // Wait a moment for peer connections to establish
    await new Promise((r) => setTimeout(r, 3000));

    const connected = nodeServer.getConnectedNodeIds();
    if (connected.length < config.CLIRFT_TOTAL_PARTIES - 1) {
      console.log(
        chalk.yellow(
          `\n  Warning: Only ${connected.length} peer(s) connected (need ${config.CLIRFT_TOTAL_PARTIES - 1})`
        )
      );
    }

    console.log(`\n  Connected peers: ${chalk.green(connected.length)}`);
    for (const id of connected) {
      console.log(`    - ${chalk.cyan(id)}`);
    }
    console.log('');

    const coordinator = new DkgCoordinator({
      nodeId: config.CLIRFT_NODE_ID,
      nodeServer,
      keyShareStore,
      myPrivateKeyPem: identity.keyPem,
      threshold: config.CLIRFT_THRESHOLD,
      totalParties: config.CLIRFT_TOTAL_PARTIES,
      timeoutMs: config.CLIRFT_DKG_TIMEOUT_MS,
    });

    // Wire DKG messages from node server to coordinator
    nodeServer.on('dkgMessage', (nodeId, msg) => {
      coordinator.handleMessage(nodeId, msg as { type: any; payload: unknown });
    });

    // Wire peer pubkeys for Round 3 share encryption
    nodeServer.onPeerIdentified((nodeId, pubkeyPem) => {
      coordinator.setPeerPubkey(nodeId, pubkeyPem);
    });
    // Seed pubkeys for peers already connected during the 3s wait
    for (const [nodeId, pubkeyPem] of nodeServer.getPeerPubkeys()) {
      coordinator.setPeerPubkey(nodeId, pubkeyPem);
    }

    console.log(chalk.cyan('  Starting DKG ceremony...\n'));

    try {
      const pkMaster = await new Promise<{ pkMaster: string; chainCode: string }>(
        (resolve, reject) => {
          coordinator.on('complete', (pkMaster, chainCode) => resolve({ pkMaster, chainCode }));
          coordinator.on('aborted', (reason) => reject(new Error(reason)));
          coordinator.initiate().catch(reject);
        }
      );

      console.log(chalk.green('\n  DKG ceremony complete!'));
      console.log(chalk.gray('  ─────────────────────────────────────────'));
      console.log(`  PK_master : ${chalk.yellow(pkMaster.pkMaster)}`);

      // Derive and display the first address
      const addrIndex = new AddressIndex(
        config.CLIRFT_DATA_DIR,
        pkMaster.pkMaster,
        pkMaster.chainCode
      );
      const firstAddr = addrIndex.deriveOne(0);
      console.log(`  Address 0 : ${chalk.green(firstAddr.address)}`);
      console.log(`  Path      : ${chalk.gray(firstAddr.path)}`);
      console.log(chalk.gray('  ─────────────────────────────────────────\n'));

      await nodeServer.stop();
      process.exit(0);
    } catch (err) {
      console.error(chalk.red('\n  DKG ceremony failed:'), err);
      await nodeServer.stop();
      process.exit(1);
    }
  });

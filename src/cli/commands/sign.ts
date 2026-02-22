import { Command } from 'commander';
import chalk from 'chalk';
import { loadConfig } from '../../config/loader';
import { NodeServer } from '../../core/NodeServer';
import { SigningCoordinator } from '../../core/signing/SigningCoordinator';
import { KeyShareStore } from '../../storage/KeyShareStore';
import { loadOrCreateNodeIdentity } from '../../network/security/NodeIdentity';
import { AddressIndex } from '../../wallet/AddressIndex';
import { RawTxData } from '../../network/protocol/Message';
import { keccak256 } from 'viem';

export const signCommand = new Command('sign')
  .description('Initiate a 2-of-3 threshold signing session for an Ethereum transaction')
  .requiredOption('--to <address>', 'Recipient Ethereum address')
  .option('--value <eth>', 'ETH value to send (decimal, e.g. "1.5")', '0')
  .option('--data <hex>', 'Contract calldata (hex)', '0x')
  .option('--index <n>', 'Derivation index of the signing address', '0')
  .option('--nonce <n>', 'Transaction nonce')
  .option('--gas-limit <n>', 'Gas limit', '21000')
  .option('--max-fee <gwei>', 'maxFeePerGas in gwei', '20')
  .option('--max-priority-fee <gwei>', 'maxPriorityFeePerGas in gwei', '1')
  .option('--dry-run', 'Sign but do not broadcast; print raw transaction hex')
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

    const keyShareStore = new KeyShareStore(
      config.CLIRFT_DATA_DIR,
      config.CLIRFT_NODE_ID,
      config.CLIRFT_STORAGE_BACKEND,
      {
        kmsKeyId: config.CLIRFT_KMS_KEY_ID,
        localPassphrase: config.CLIRFT_LOCAL_PASSPHRASE,
      }
    );

    if (!keyShareStore.exists()) {
      console.error(
        chalk.red('No key share found.'),
        'Run',
        chalk.yellow('clirft keygen'),
        'first.'
      );
      process.exit(1);
    }

    // Load ceremony metadata for PK_master / chainCode
    const ceremony = keyShareStore.loadCeremonyMetadata();
    if (!ceremony) {
      console.error(chalk.red('No ceremony metadata found.'));
      process.exit(1);
    }

    // Derive signing address
    const addrIndex = new AddressIndex(
      config.CLIRFT_DATA_DIR,
      ceremony.pkMaster,
      ceremony.chainCode
    );
    const signingEntry = addrIndex.deriveOne(parseInt(options.index, 10));

    const gweiToWei = (gwei: string) => (BigInt(Math.round(parseFloat(gwei) * 1e9)) * 1_000_000_000n).toString();

    const rawTx: RawTxData = {
      to: options.to,
      value: (BigInt(Math.round(parseFloat(options.value) * 1e18))).toString(),
      data: options.data,
      nonce: parseInt(options.nonce ?? '0', 10),
      gasLimit: options.gasLimit,
      maxFeePerGas: gweiToWei(options.maxFee),
      maxPriorityFeePerGas: gweiToWei(options.maxPriorityFee),
      chainId: config.CLIRFT_CHAIN_ID,
    };

    // Compute a simplified txHash (in production use viem's serializeTransaction + keccak256)
    const txDataStr = JSON.stringify({ ...rawTx, type: '0x02' });
    const txHash = keccak256(Buffer.from(txDataStr) as unknown as `0x${string}`).slice(2);

    const identity = loadOrCreateNodeIdentity(config.CLIRFT_DATA_DIR, config.CLIRFT_NODE_ID);

    console.log(chalk.cyan('\n  CLIRift Signing Session'));
    console.log(chalk.gray('  ─────────────────────────────────────────'));
    console.log(`  From     : ${chalk.green(signingEntry.address)} (index ${options.index})`);
    console.log(`  To       : ${chalk.yellow(options.to)}`);
    console.log(`  Value    : ${chalk.yellow(options.value)} ETH`);
    console.log(`  Chain ID : ${chalk.yellow(config.CLIRFT_CHAIN_ID)}`);
    console.log(`  Tx Hash  : ${chalk.gray(txHash)}`);
    console.log(chalk.gray('  ─────────────────────────────────────────\n'));

    const nodeServer = new NodeServer(config);
    await nodeServer.start();

    // Wait for peer connections
    await new Promise((r) => setTimeout(r, 3000));

    const coordinator = new SigningCoordinator({
      nodeId: config.CLIRFT_NODE_ID,
      nodeServer,
      keyShareStore,
      myPrivateKeyPem: identity.keyPem,
      timeoutMs: config.CLIRFT_SIGN_TIMEOUT_MS,
    });

    nodeServer.on('signMessage', (nodeId, msg) => {
      coordinator.handleMessage(nodeId, msg as { type: any; payload: unknown });
    });

    console.log(chalk.cyan('  Starting signing session...'));

    try {
      const result = await new Promise<{ sig: { r: string; s: string; v: number }; signedTxHex: string }>(
        (resolve, reject) => {
          coordinator.on('complete', (sig, signedTxHex) => resolve({ sig, signedTxHex }));
          coordinator.on('aborted', (reason) => reject(new Error(reason)));
          coordinator.initiate(rawTx, signingEntry.path, txHash).catch(reject);
        }
      );

      console.log(chalk.green('\n  Transaction signed!'));
      console.log(chalk.gray('  ─────────────────────────────────────────'));
      console.log(`  r        : ${chalk.gray(result.sig.r)}`);
      console.log(`  s        : ${chalk.gray(result.sig.s)}`);
      console.log(`  v        : ${chalk.yellow(result.sig.v)}`);
      console.log(`  Raw tx   : ${chalk.cyan(result.signedTxHex)}`);

      if (!options.dryRun && config.CLIRFT_ETH_RPC_URL) {
        console.log(chalk.yellow('\n  Broadcasting to Ethereum network...'));
        // In production: use viem's publicClient.sendRawTransaction(result.signedTxHex)
        console.log(chalk.gray('  (RPC broadcast not implemented in this build)'));
      } else if (options.dryRun) {
        console.log(chalk.gray('\n  Dry run — transaction not broadcast.'));
      }

      console.log('');
      await nodeServer.stop();
      process.exit(0);
    } catch (err) {
      console.error(chalk.red('\n  Signing failed:'), err);
      await nodeServer.stop();
      process.exit(1);
    }
  });

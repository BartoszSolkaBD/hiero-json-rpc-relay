// SPDX-License-Identifier: Apache-2.0

/**
 * Receipt serialization per Ethereum Yellow Paper and EIP-2718.
 *
 * Yellow Paper: receipt is RLP of the 4-tuple
 *   (receipt_root_or_status, cumulative_gas_used, logs_bloom, logs).
 * Post-Byzantium: first field is status (empty for 0, 0x01 for 1) or 32-byte state root.
 * Each log: RLP([address, topics[], data]).
 *
 * EIP-2718: for typed txs (type !== 0), wire format is type_byte || RLP(above 4-tuple).
 */

import { RLP } from '@ethereumjs/rlp';
import { bytesToInt, concatBytes, hexToBytes, intToBytes } from '@ethereumjs/util';

import { prepend0x, toHexString } from '../formatters';
import constants from './constants';
import type { Log } from './model';
import { IReceiptRlpInput } from './types/IReceiptRlpInput';

/**
 * Converts receipt logs into the RLP encoded log structure.
 *
 * Each log becomes a 3-tuple [address, topics[], data] per the Yellow Paper
 * (address and data as bytes; topics as array of 32-byte topic hashes).
 *
 * @param logs - The logs array from the transaction receipt (see {@link Log}).
 * @returns Array of [address, topics, data] as Uint8Arrays for RLP encoding.
 */
function encodeLogsForReceipt(logs: Log[]): [Uint8Array, Uint8Array[], Uint8Array][] {
  return logs.map((log) => [hexToBytes(log.address), log.topics.map((t) => hexToBytes(t)), hexToBytes(log.data)]);
}

/**
 * Encodes a single transaction receipt to EIP-2718 binary form.
 *
 * Produces the RLP-encoded 4-tuple (receipt_root_or_status, cumulative_gas_used,
 * logs_bloom, logs) per the Ethereum Yellow Paper. For typed transactions (type !== 0),
 * the output is the single-byte type prefix followed by that RLP payload (EIP-2718).
 *
 * Based on section 4.4.1 (Transaction Receipt) from the Ethereum Yellow Paper: https://ethereum.github.io/yellowpaper/paper.pdf
 *
 * @param receipt - The transaction receipt to encode (see {@link ITransactionReceipt}).
 * @returns Hex string (0x-prefixed) of the encoded receipt, suitable for receipts root hashing.
 */
export function encodeReceiptToHex(receipt: IReceiptRlpInput): string {
  const txType = receipt.type !== null ? bytesToInt(hexToBytes(receipt.type)) : 0;

  // First field: receipt root or status (post-Byzantium)
  let receiptRootOrStatus: Uint8Array;
  if (receipt.root && receipt.root.length > 2) {
    receiptRootOrStatus = hexToBytes(receipt.root);
  } else if (receipt.status && bytesToInt(hexToBytes(receipt.status)) === 0) {
    receiptRootOrStatus = new Uint8Array(0);
  } else {
    receiptRootOrStatus = hexToBytes(constants.ONE_HEX);
  }

  const cumulativeGasUsed = receipt.cumulativeGasUsed;
  const cumulativeGasUsedBytes =
    BigInt(cumulativeGasUsed) === BigInt(0)
      ? new Uint8Array(0)
      : hexToBytes(prepend0x(BigInt(cumulativeGasUsed).toString(16))); // canonical RLP encoding (no leading zeros)

  const encodedList = RLP.encode([
    receiptRootOrStatus,
    cumulativeGasUsedBytes,
    hexToBytes(receipt.logsBloom),
    encodeLogsForReceipt(receipt.logs),
  ]);

  if (txType === 0) {
    return prepend0x(toHexString(encodedList));
  }
  const withPrefix = concatBytes(intToBytes(txType), encodedList);
  return prepend0x(toHexString(withPrefix));
}

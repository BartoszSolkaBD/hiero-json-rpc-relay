// SPDX-License-Identifier: Apache-2.0

import { ASCIIToHex, isHex, nanOrNumberTo0x, numberTo0x, prepend0x, toHash32 } from '../../formatters';
import { LogsBloomUtils } from '../../logsBloomUtils';
import constants from '../constants';
import { Log } from '../model';
import { ITransactionReceipt } from '../types';
import { IReceiptRlpInput } from '../types/IReceiptRlpInput';

/**
 * Parameters specific to creating a synthetic transaction receipt from logs
 */
interface ISyntheticTransactionReceiptParams {
  syntheticLogs: Log[];
  gasPriceForTimestamp: string;
}

/**
 * Parameters specific to creating a regular transaction receipt from mirror node data
 */
interface IRegularTransactionReceiptParams {
  effectiveGas: string;
  from: string;
  logs: Log[];
  receiptResponse: any;
  to: string | null;
}

interface IRegularTransactionReceiptRlpInputParams {
  logs: Log[];
  receiptResponse: any;
  blockGasUsedBeforeTransaction: number;
}

/**
 * Factory for creating different types of transaction receipts
 */
class TransactionReceiptFactory {
  /**
   * Creates a synthetic transaction receipt from a log
   *
   * @param params Parameters required to create a synthetic transaction receipt
   * @returns {ITransactionReceipt} Transaction receipt for the synthetic transaction
   */
  public static createSyntheticReceipt(params: ISyntheticTransactionReceiptParams): ITransactionReceipt {
    const { syntheticLogs, gasPriceForTimestamp } = params;

    return {
      blockHash: syntheticLogs[0].blockHash,
      blockNumber: syntheticLogs[0].blockNumber,
      contractAddress: syntheticLogs[0].address,
      cumulativeGasUsed: constants.ZERO_HEX,
      effectiveGasPrice: gasPriceForTimestamp,
      from: constants.ZERO_ADDRESS_HEX,
      gasUsed: constants.ZERO_HEX,
      logs: [syntheticLogs[0]],
      logsBloom: LogsBloomUtils.buildLogsBloom(syntheticLogs[0].address, syntheticLogs[0].topics),
      root: constants.DEFAULT_ROOT_HASH,
      status: constants.ONE_HEX,
      to: syntheticLogs[0].address,
      transactionHash: syntheticLogs[0].transactionHash,
      transactionIndex: syntheticLogs[0].transactionIndex,
      type: constants.ZERO_HEX, // fallback to 0x0 from HAPI transactions
    };
  }

  /**
   * Creates a minimal receipt payload for RLP-encoding of a synthetic transaction.
   *
   * Builds an `IReceiptRlpInput` from synthetic logs only, without resolving any
   * addresses or constructing a full `ITransactionReceipt`. The returned shape
   * contains the fields required for Yellow Paper receipt encoding, including a zero
   * cumulative gas used, zero gas used, a logs bloom computed from the first
   * synthetic log, default root and status values, the transaction index from
   * the first log, and a fallback type of `0x0`.
   *
   * @param syntheticLogs - Logs belonging to the synthetic transaction.
   * @returns Minimal receipt data suitable for RLP encoding.
   */
  public static createSyntheticReceiptRlpInput(syntheticLogs: Log[]): IReceiptRlpInput {
    return {
      cumulativeGasUsed: constants.ZERO_HEX,
      logs: syntheticLogs,
      logsBloom: LogsBloomUtils.buildLogsBloom(syntheticLogs[0].address, syntheticLogs[0].topics),
      root: constants.DEFAULT_ROOT_HASH,
      status: constants.ONE_HEX,
      transactionIndex: syntheticLogs[0].transactionIndex,
      type: constants.ZERO_HEX, // fallback to 0x0 from HAPI transactions
    };
  }

  /**
   * Creates a regular transaction receipt from mirror node contract result data
   *
   * Handles the correction of transaction receipt `to` field for contract creation transactions.
   *
   * This logic addresses a discrepancy between Hedera and standard Ethereum behavior regarding
   * the `to` field in transaction receipts. When a smart contract is deployed:
   *
   * 1. In standard Ethereum JSON-RPC, if the original transaction had a null `to` field
   *    (contract creation), the transaction receipt also reports a null `to` field.
   *
   * 2. Hedera Mirror Node, however, automatically populates the `to` field with the
   *    address of the newly created contract.
   *
   * The code checks if a contract was directly created by the transaction (rather than created by
   * another contract) by checking if the contract's ID appears in the `created_contract_ids` array.
   * If so, it resets the `to` field to null to match standard Ethereum JSON-RPC behavior.
   *
   * This ensures compatibility with Ethereum tooling that expects standard transaction receipt formats.
   * The handling covers various scenarios:
   *
   * - Direct contract deployment (empty `to` field)
   * - Contract creation via factory contracts
   * - Method calls that don't create contracts
   * - Transactions with populated `to` fields that create child contracts
   *
   * @param params Parameters required to create a regular transaction receipt
   * @param resolveEvmAddressFn Function to resolve EVM addresses
   * @returns {ITransactionReceipt} Transaction receipt for the regular transaction
   */
  public static createRegularReceipt(params: IRegularTransactionReceiptParams): ITransactionReceipt {
    const { receiptResponse, effectiveGas, from, logs } = params;
    let { to } = params;

    // Determine contract address if it exists
    const contractAddress = TransactionReceiptFactory.getContractAddressFromReceipt(receiptResponse);

    if (receiptResponse.created_contract_ids.includes(receiptResponse.contract_id)) {
      to = null;
    }

    // Create the receipt object
    const receipt: ITransactionReceipt = {
      blockHash: toHash32(receiptResponse.block_hash),
      blockNumber: numberTo0x(receiptResponse.block_number),
      from: from,
      to: to,
      cumulativeGasUsed: numberTo0x(receiptResponse.block_gas_used),
      gasUsed: nanOrNumberTo0x(receiptResponse.gas_used),
      contractAddress: contractAddress,
      logs: logs,
      logsBloom: receiptResponse.bloom === constants.EMPTY_HEX ? constants.EMPTY_BLOOM : receiptResponse.bloom,
      transactionHash: toHash32(receiptResponse.hash),
      transactionIndex: numberTo0x(receiptResponse.transaction_index),
      effectiveGasPrice: effectiveGas,
      root: receiptResponse.root || constants.DEFAULT_ROOT_HASH,
      status: receiptResponse.status,
      type: nanOrNumberTo0x(receiptResponse.type),
    };

    // Add revert reason if available
    if (receiptResponse.error_message) {
      receipt.revertReason = isHex(prepend0x(receiptResponse.error_message))
        ? receiptResponse.error_message
        : prepend0x(ASCIIToHex(receiptResponse.error_message));
    }

    return receipt;
  }

  /**
   * Creates a minimal receipt payload for RLP-encoding of a regular transaction.
   *
   * Builds an `IReceiptRlpInput` from mirror node contract result data and the
   * running cumulative gas used before this transaction. The returned shape
   * contains only the fields required for Yellow Paper receipt encoding, including the updated cumulative gas used,
   * logs and bloom, root and status, transaction index, and normalized type.
   * @param params - Parameters required to build the RLP input, including
   *   contract result data, associated logs, and the cumulative gas used prior
   *   to this transaction.
   * @returns Minimal receipt data suitable for RLP encoding.
   */
  public static createReceiptRlpInput(params: IRegularTransactionReceiptRlpInputParams): IReceiptRlpInput {
    const { receiptResponse, logs, blockGasUsedBeforeTransaction } = params;

    return {
      cumulativeGasUsed: numberTo0x(blockGasUsedBeforeTransaction + receiptResponse.gas_used),
      logs: logs,
      logsBloom: receiptResponse.bloom === constants.EMPTY_HEX ? constants.EMPTY_BLOOM : receiptResponse.bloom,
      root: receiptResponse.root || constants.DEFAULT_ROOT_HASH,
      status: receiptResponse.status,
      transactionIndex: numberTo0x(receiptResponse.transaction_index),
      type: nanOrNumberTo0x(receiptResponse.type),
    };
  }

  /**
   * Helper method to determine if a receipt response includes a contract address
   *
   * @param receiptResponse Mirror node contract result response
   * @returns {string} Contract address or null
   */
  private static getContractAddressFromReceipt(receiptResponse: any): string {
    const isCreationViaSystemContract = constants.HTS_CREATE_FUNCTIONS_SELECTORS.includes(
      receiptResponse.function_parameters.substring(0, constants.FUNCTION_SELECTOR_CHAR_LENGTH),
    );

    if (!isCreationViaSystemContract) {
      return receiptResponse.address;
    }

    // Handle system contract creation
    // reason for substring is described in the design doc in this repo: docs/design/hts_address_tx_receipt.md
    const tokenAddress = receiptResponse.call_result.substring(receiptResponse.call_result.length - 40);
    return prepend0x(tokenAddress);
  }
}

export {
  ISyntheticTransactionReceiptParams,
  IRegularTransactionReceiptParams,
  IRegularTransactionReceiptRlpInputParams,
  TransactionReceiptFactory,
};

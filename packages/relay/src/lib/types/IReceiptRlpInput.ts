// SPDX-License-Identifier: Apache-2.0

import { Log } from '../model';

export interface IReceiptRlpInput {
  cumulativeGasUsed: string;
  logs: Log[];
  logsBloom: string;
  root: string;
  status: string;
  transactionIndex: string | null;
  type: string | null;
}

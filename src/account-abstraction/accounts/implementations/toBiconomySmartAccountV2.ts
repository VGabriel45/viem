import { type Address, parseAbi } from 'abitype'
import {
  type WebAuthnData,
  parseSignature as parseP256Signature,
} from 'webauthn-p256'

import type { LocalAccount } from '../../../accounts/types.js'
import { readContract } from '../../../actions/public/readContract.js'
import type { Client } from '../../../clients/createClient.js'
import { entryPoint06Address } from '../../../constants/address.js'
import { BaseError } from '../../../errors/base.js'
import type { Hash, Hex } from '../../../types/misc.js'
import type { Assign, OneOf, Prettify } from '../../../types/utils.js'
import { encodeAbiParameters } from '../../../utils/abi/encodeAbiParameters.js'
import { encodeFunctionData } from '../../../utils/abi/encodeFunctionData.js'
import { stringToHex } from '../../../utils/encoding/toHex.js'
import { hashMessage } from '../../../utils/signature/hashMessage.js'
import { entryPoint06Abi } from '../../constants/abis.js'
import type { UserOperation } from '../../types/userOperation.js'
import { getUserOperationHash } from '../../utils/userOperation/getUserOperationHash.js'
import { toSmartAccount } from '../toSmartAccount.js'
import type {
  SmartAccount,
  SmartAccountImplementation,
  WebAuthnAccount,
} from '../types.js'

export type toBiconomySmartAccountV2Parameters = {
  address?: Address | undefined
  client: Client
  owner: OneOf<LocalAccount | WebAuthnAccount>
  nonce?: bigint | undefined
}

export type toBiconomySmartAccountV2ReturnType = Prettify<
  SmartAccount<BiconomySmartAccountImplementation>
>

export type BiconomySmartAccountImplementation = Assign<
  SmartAccountImplementation<
    typeof entryPoint06Abi,
    '0.6',
    { abi: typeof abi; factory: { abi: typeof factoryAbi; address: Address } }
  >,
  {}
>

const DEFAULT_ECDSA_MODULE_ADDRESS =
  '0x0000001c5b32F37F5beA87BDD5374eB2aC54eA8e'

/**
 * @description Create a Biconomy Smart Account.
 *
 * @param parameters - {@link toBiconomySmartAccountV2Parameters}
 * @returns Biconomy Smart Account. {@link toBiconomySmartAccountV2ReturnType}
 *
 * @example
 * import { toBiconomySmartAccountV2 } from 'viem/account-abstraction'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { client } from './client.js'
 *
 * const account = toBiconomySmartAccountV2({
 *   client,
 *   owners: [privateKeyToAccount('0x...')],
 * })
 */
export async function toBiconomySmartAccountV2(
  parameters: toBiconomySmartAccountV2Parameters,
): Promise<toBiconomySmartAccountV2ReturnType> {
  const { address, client, owner, nonce = 0n } = parameters

  const entryPoint = {
    abi: entryPoint06Abi,
    address: entryPoint06Address,
    version: '0.6',
  } as const

  const factory = {
    abi: factoryAbi,
    address: '0x000000a56Aaca3e9a4C479ea6b6CD0DbcB6634F5',
  } as const

  return toSmartAccount({
    client,
    entryPoint,

    extend: { abi, factory },

    async encodeCalls(calls) {
      if (calls.length === 1)
        return encodeFunctionData({
          abi,
          functionName: 'execute',
          args: [calls[0].to, calls[0].value ?? 0n, calls[0].data ?? '0x'],
        })
      return encodeFunctionData({
        abi,
        functionName: 'executeBatch_y6U',
        args: [
          calls.map((call) => call.to),
          calls.map((call) => call.value ?? 0n),
          calls.map((call) => call.data ?? '0x'),
        ],
      })
    },

    async getAddress() {
      if (address) return address
      const ecdsaOwnerAddress = owner.address ?? '0x'
      const moduleRegistryParsedAbi = parseAbi([
        'function initForSmartAccount(address owner)',
      ])
      const ecdsaOwnershipInitData = encodeFunctionData({
        abi: moduleRegistryParsedAbi,
        functionName: 'initForSmartAccount',
        args: [ecdsaOwnerAddress],
      })
      return await readContract(client, {
        ...factory,
        functionName: 'getAddressForCounterFactualAccount',
        args: [DEFAULT_ECDSA_MODULE_ADDRESS, ecdsaOwnershipInitData, nonce],
      })
    },

    async getFactoryArgs() {
      const ecdsaOwnerAddress = owner.address ?? '0x'
      const moduleRegistryParsedAbi = parseAbi([
        'function initForSmartAccount(address owner)',
      ])
      const ecdsaOwnershipInitData = encodeFunctionData({
        abi: moduleRegistryParsedAbi,
        functionName: 'initForSmartAccount',
        args: [ecdsaOwnerAddress],
      })
      const factoryData = encodeFunctionData({
        abi: factory.abi,
        functionName: 'deployCounterFactualAccount',
        args: [DEFAULT_ECDSA_MODULE_ADDRESS, ecdsaOwnershipInitData, nonce],
      })
      return { factory: factory.address, factoryData }
    },

    async getNonce({ key = 0n } = {}) {
      const address = await this.getAddress()
      const nonce = await readContract(client, {
        abi: parseAbi([
          'function getNonce(address, uint192) pure returns (uint256)',
        ]),
        address: entryPoint.address,
        functionName: 'getNonce',
        args: [address, key],
      })
      return nonce
    },

    async getStubSignature() {
      return wrapSignature({
        signature:
          '0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c',
      })
    },

    async signMessage(parameters) {
      const message = parameters.message
      const signature = (await sign({
        hash: hashMessage(message),
        owner,
      })) as Hex

      return wrapSignature({ signature }) as Hex
    },

    async signTypedData(parameters) {
      throw new Error(`signTypedData not supported. ${parameters}`)
    },

    async signUserOperation(parameters) {
      const { chainId = client.chain!.id, ...userOperation } = parameters

      const address = await this.getAddress()
      const hash = getUserOperationHash({
        chainId,
        entryPointAddress: entryPoint.address,
        entryPointVersion: entryPoint.version,
        userOperation: {
          ...(userOperation as unknown as UserOperation),
          sender: address,
        },
      })

      const signature = await sign({ hash, owner })

      return wrapSignature({
        signature,
      })
    },

    userOperation: {
      async estimateGas(userOperation) {
        if (owner.type !== 'webAuthn') return

        // Accounts with WebAuthn owner require a minimum verification gas limit of 800,000.
        return {
          verificationGasLimit: BigInt(
            Math.max(Number(userOperation.verificationGasLimit ?? 0n), 800_000),
          ),
        }
      },
    },
  })
}

/////////////////////////////////////////////////////////////////////////////////////////////
// Utilities
/////////////////////////////////////////////////////////////////////////////////////////////

/** @internal */
export async function sign({
  hash,
  owner,
}: { hash: Hash; owner: OneOf<LocalAccount | WebAuthnAccount> }) {
  // WebAuthn Account (Passkey)
  if (owner.type === 'webAuthn') {
    const { signature, webauthn } = await owner.sign({
      hash,
    })
    return toWebAuthnSignature({ signature, webauthn })
  }

  if (owner.sign) return owner.sign({ hash })

  throw new BaseError('`owner` does not support raw sign.')
}

/** @internal */
export function toWebAuthnSignature({
  webauthn,
  signature,
}: {
  webauthn: WebAuthnData
  signature: Hex
}) {
  const { r, s } = parseP256Signature(signature)
  return encodeAbiParameters(
    [
      {
        components: [
          {
            name: 'authenticatorData',
            type: 'bytes',
          },
          { name: 'clientDataJSON', type: 'bytes' },
          { name: 'challengeIndex', type: 'uint256' },
          { name: 'typeIndex', type: 'uint256' },
          {
            name: 'r',
            type: 'uint256',
          },
          {
            name: 's',
            type: 'uint256',
          },
        ],
        type: 'tuple',
      },
    ],
    [
      {
        authenticatorData: webauthn.authenticatorData,
        clientDataJSON: stringToHex(webauthn.clientDataJSON),
        challengeIndex: BigInt(webauthn.challengeIndex),
        typeIndex: BigInt(webauthn.typeIndex),
        r,
        s,
      },
    ],
  )
}

/** @internal */
export function wrapSignature(parameters: {
  ownerIndex?: number | undefined
  signature: Hex
}) {
  let signature = parameters.signature
  const potentiallyIncorrectV = Number.parseInt(signature.slice(-2), 16)
  if (![27, 28].includes(potentiallyIncorrectV)) {
    const correctV = potentiallyIncorrectV + 27
    signature = signature.slice(0, -2) + correctV.toString(16)
  }
  signature = encodeAbiParameters(
    [{ type: 'bytes' }, { type: 'address' }],
    [signature as Hex, DEFAULT_ECDSA_MODULE_ADDRESS],
  )

  return signature as Hex
}

/////////////////////////////////////////////////////////////////////////////////////////////
// Constants
/////////////////////////////////////////////////////////////////////////////////////////////

const abi = [
  {
    inputs: [
      {
        internalType: 'contract IEntryPoint',
        name: 'anEntryPoint',
        type: 'address',
      },
    ],
    stateMutability: 'nonpayable',
    type: 'constructor',
  },
  { inputs: [], name: 'AlreadyInitialized', type: 'error' },
  { inputs: [], name: 'BaseImplementationCannotBeZero', type: 'error' },
  {
    inputs: [{ internalType: 'address', name: 'caller', type: 'address' }],
    name: 'CallerIsNotAnEntryPoint',
    type: 'error',
  },
  {
    inputs: [{ internalType: 'address', name: 'caller', type: 'address' }],
    name: 'CallerIsNotEntryPoint',
    type: 'error',
  },
  {
    inputs: [{ internalType: 'address', name: 'caller', type: 'address' }],
    name: 'CallerIsNotEntryPointOrOwner',
    type: 'error',
  },
  {
    inputs: [{ internalType: 'address', name: 'caller', type: 'address' }],
    name: 'CallerIsNotEntryPointOrSelf',
    type: 'error',
  },
  {
    inputs: [{ internalType: 'address', name: 'caller', type: 'address' }],
    name: 'CallerIsNotOwner',
    type: 'error',
  },
  {
    inputs: [{ internalType: 'address', name: 'caller', type: 'address' }],
    name: 'CallerIsNotSelf',
    type: 'error',
  },
  { inputs: [], name: 'DelegateCallsOnly', type: 'error' },
  { inputs: [], name: 'EntryPointCannotBeZero', type: 'error' },
  { inputs: [], name: 'HandlerCannotBeZero', type: 'error' },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'implementationAddress',
        type: 'address',
      },
    ],
    name: 'InvalidImplementation',
    type: 'error',
  },
  {
    inputs: [{ internalType: 'address', name: 'caller', type: 'address' }],
    name: 'MixedAuthFail',
    type: 'error',
  },
  {
    inputs: [{ internalType: 'address', name: 'module', type: 'address' }],
    name: 'ModuleAlreadyEnabled',
    type: 'error',
  },
  {
    inputs: [
      { internalType: 'address', name: 'expectedModule', type: 'address' },
      { internalType: 'address', name: 'returnedModule', type: 'address' },
      { internalType: 'address', name: 'prevModule', type: 'address' },
    ],
    name: 'ModuleAndPrevModuleMismatch',
    type: 'error',
  },
  {
    inputs: [{ internalType: 'address', name: 'module', type: 'address' }],
    name: 'ModuleCannotBeZeroOrSentinel',
    type: 'error',
  },
  {
    inputs: [{ internalType: 'address', name: 'module', type: 'address' }],
    name: 'ModuleNotEnabled',
    type: 'error',
  },
  { inputs: [], name: 'ModulesAlreadyInitialized', type: 'error' },
  { inputs: [], name: 'ModulesSetupExecutionFailed', type: 'error' },
  { inputs: [], name: 'OwnerCanNotBeSelf', type: 'error' },
  { inputs: [], name: 'OwnerCannotBeZero', type: 'error' },
  { inputs: [], name: 'OwnerProvidedIsSame', type: 'error' },
  { inputs: [], name: 'TransferToZeroAddressAttempt', type: 'error' },
  {
    inputs: [
      { internalType: 'uint256', name: 'destLength', type: 'uint256' },
      { internalType: 'uint256', name: 'valueLength', type: 'uint256' },
      { internalType: 'uint256', name: 'funcLength', type: 'uint256' },
      { internalType: 'uint256', name: 'operationLength', type: 'uint256' },
    ],
    name: 'WrongBatchProvided',
    type: 'error',
  },
  {
    inputs: [
      { internalType: 'bytes', name: 'contractSignature', type: 'bytes' },
    ],
    name: 'WrongContractSignature',
    type: 'error',
  },
  {
    inputs: [
      { internalType: 'uint256', name: 'uintS', type: 'uint256' },
      {
        internalType: 'uint256',
        name: 'contractSignatureLength',
        type: 'uint256',
      },
      { internalType: 'uint256', name: 'signatureLength', type: 'uint256' },
    ],
    name: 'WrongContractSignatureFormat',
    type: 'error',
  },
  {
    inputs: [
      {
        internalType: 'address',
        name: 'moduleAddressProvided',
        type: 'address',
      },
    ],
    name: 'WrongValidationModule',
    type: 'error',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'previousHandler',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'handler',
        type: 'address',
      },
    ],
    name: 'ChangedFallbackHandler',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'address',
        name: 'module',
        type: 'address',
      },
    ],
    name: 'DisabledModule',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'address',
        name: 'module',
        type: 'address',
      },
    ],
    name: 'EnabledModule',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, internalType: 'address', name: 'to', type: 'address' },
      {
        indexed: true,
        internalType: 'uint256',
        name: 'value',
        type: 'uint256',
      },
      { indexed: true, internalType: 'bytes', name: 'data', type: 'bytes' },
      {
        indexed: false,
        internalType: 'enum Enum.Operation',
        name: 'operation',
        type: 'uint8',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'txGas',
        type: 'uint256',
      },
    ],
    name: 'ExecutionFailure',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'module',
        type: 'address',
      },
    ],
    name: 'ExecutionFromModuleFailure',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'module',
        type: 'address',
      },
    ],
    name: 'ExecutionFromModuleSuccess',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      { indexed: true, internalType: 'address', name: 'to', type: 'address' },
      {
        indexed: true,
        internalType: 'uint256',
        name: 'value',
        type: 'uint256',
      },
      { indexed: true, internalType: 'bytes', name: 'data', type: 'bytes' },
      {
        indexed: false,
        internalType: 'enum Enum.Operation',
        name: 'operation',
        type: 'uint8',
      },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'txGas',
        type: 'uint256',
      },
    ],
    name: 'ExecutionSuccess',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'oldImplementation',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'newImplementation',
        type: 'address',
      },
    ],
    name: 'ImplementationUpdated',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: 'address',
        name: 'module',
        type: 'address',
      },
      { indexed: false, internalType: 'address', name: 'to', type: 'address' },
      {
        indexed: false,
        internalType: 'uint256',
        name: 'value',
        type: 'uint256',
      },
      { indexed: false, internalType: 'bytes', name: 'data', type: 'bytes' },
      {
        indexed: false,
        internalType: 'enum Enum.Operation',
        name: 'operation',
        type: 'uint8',
      },
    ],
    name: 'ModuleTransaction',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'sender',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'uint256',
        name: 'value',
        type: 'uint256',
      },
    ],
    name: 'SmartAccountReceivedNativeToken',
    type: 'event',
  },
  { stateMutability: 'nonpayable', type: 'fallback' },
  {
    inputs: [],
    name: 'VERSION',
    outputs: [{ internalType: 'string', name: '', type: 'string' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'addDeposit',
    outputs: [],
    stateMutability: 'payable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'prevModule', type: 'address' },
      { internalType: 'address', name: 'module', type: 'address' },
    ],
    name: 'disableModule',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'address', name: 'module', type: 'address' }],
    name: 'enableModule',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [],
    name: 'entryPoint',
    outputs: [
      { internalType: 'contract IEntryPoint', name: '', type: 'address' },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address[]', name: 'to', type: 'address[]' },
      { internalType: 'uint256[]', name: 'value', type: 'uint256[]' },
      { internalType: 'bytes[]', name: 'data', type: 'bytes[]' },
      {
        internalType: 'enum Enum.Operation[]',
        name: 'operations',
        type: 'uint8[]',
      },
    ],
    name: 'execBatchTransactionFromModule',
    outputs: [{ internalType: 'bool', name: 'success', type: 'bool' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'to', type: 'address' },
      { internalType: 'uint256', name: 'value', type: 'uint256' },
      { internalType: 'bytes', name: 'data', type: 'bytes' },
      { internalType: 'enum Enum.Operation', name: 'operation', type: 'uint8' },
      { internalType: 'uint256', name: 'txGas', type: 'uint256' },
    ],
    name: 'execTransactionFromModule',
    outputs: [{ internalType: 'bool', name: 'success', type: 'bool' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'to', type: 'address' },
      { internalType: 'uint256', name: 'value', type: 'uint256' },
      { internalType: 'bytes', name: 'data', type: 'bytes' },
      { internalType: 'enum Enum.Operation', name: 'operation', type: 'uint8' },
    ],
    name: 'execTransactionFromModule',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'to', type: 'address' },
      { internalType: 'uint256', name: 'value', type: 'uint256' },
      { internalType: 'bytes', name: 'data', type: 'bytes' },
      { internalType: 'enum Enum.Operation', name: 'operation', type: 'uint8' },
    ],
    name: 'execTransactionFromModuleReturnData',
    outputs: [
      { internalType: 'bool', name: 'success', type: 'bool' },
      { internalType: 'bytes', name: 'returnData', type: 'bytes' },
    ],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'dest', type: 'address' },
      { internalType: 'uint256', name: 'value', type: 'uint256' },
      { internalType: 'bytes', name: 'func', type: 'bytes' },
    ],
    name: 'execute',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address[]', name: 'dest', type: 'address[]' },
      { internalType: 'uint256[]', name: 'value', type: 'uint256[]' },
      { internalType: 'bytes[]', name: 'func', type: 'bytes[]' },
    ],
    name: 'executeBatch',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address[]', name: 'dest', type: 'address[]' },
      { internalType: 'uint256[]', name: 'value', type: 'uint256[]' },
      { internalType: 'bytes[]', name: 'func', type: 'bytes[]' },
    ],
    name: 'executeBatch_y6U',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'dest', type: 'address' },
      { internalType: 'uint256', name: 'value', type: 'uint256' },
      { internalType: 'bytes', name: 'func', type: 'bytes' },
    ],
    name: 'execute_ncC',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [],
    name: 'getDeposit',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'getFallbackHandler',
    outputs: [{ internalType: 'address', name: '_handler', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'getImplementation',
    outputs: [
      { internalType: 'address', name: '_implementation', type: 'address' },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'start', type: 'address' },
      { internalType: 'uint256', name: 'pageSize', type: 'uint256' },
    ],
    name: 'getModulesPaginated',
    outputs: [
      { internalType: 'address[]', name: 'array', type: 'address[]' },
      { internalType: 'address', name: 'next', type: 'address' },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'handler', type: 'address' },
      { internalType: 'address', name: 'moduleSetupContract', type: 'address' },
      { internalType: 'bytes', name: 'moduleSetupData', type: 'bytes' },
    ],
    name: 'init',
    outputs: [{ internalType: 'address', name: '', type: 'address' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'address', name: 'module', type: 'address' }],
    name: 'isModuleEnabled',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'bytes32', name: 'dataHash', type: 'bytes32' },
      { internalType: 'bytes', name: 'signature', type: 'bytes' },
    ],
    name: 'isValidSignature',
    outputs: [{ internalType: 'bytes4', name: '', type: 'bytes4' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'uint192', name: '_key', type: 'uint192' }],
    name: 'nonce',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    name: 'noncesDeprecated',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'ownerDeprecated',
    outputs: [{ internalType: 'address', name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'address', name: 'handler', type: 'address' }],
    name: 'setFallbackHandler',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'setupContract', type: 'address' },
      { internalType: 'bytes', name: 'setupData', type: 'bytes' },
    ],
    name: 'setupAndEnableModule',
    outputs: [{ internalType: 'address', name: '', type: 'address' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'bytes4', name: '_interfaceId', type: 'bytes4' }],
    name: 'supportsInterface',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: '_implementation', type: 'address' },
    ],
    name: 'updateImplementation',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      {
        components: [
          { internalType: 'address', name: 'sender', type: 'address' },
          { internalType: 'uint256', name: 'nonce', type: 'uint256' },
          { internalType: 'bytes', name: 'initCode', type: 'bytes' },
          { internalType: 'bytes', name: 'callData', type: 'bytes' },
          { internalType: 'uint256', name: 'callGasLimit', type: 'uint256' },
          {
            internalType: 'uint256',
            name: 'verificationGasLimit',
            type: 'uint256',
          },
          {
            internalType: 'uint256',
            name: 'preVerificationGas',
            type: 'uint256',
          },
          { internalType: 'uint256', name: 'maxFeePerGas', type: 'uint256' },
          {
            internalType: 'uint256',
            name: 'maxPriorityFeePerGas',
            type: 'uint256',
          },
          { internalType: 'bytes', name: 'paymasterAndData', type: 'bytes' },
          { internalType: 'bytes', name: 'signature', type: 'bytes' },
        ],
        internalType: 'struct UserOperation',
        name: 'userOp',
        type: 'tuple',
      },
      { internalType: 'bytes32', name: 'userOpHash', type: 'bytes32' },
      { internalType: 'uint256', name: 'missingAccountFunds', type: 'uint256' },
    ],
    name: 'validateUserOp',
    outputs: [
      { internalType: 'uint256', name: 'validationData', type: 'uint256' },
    ],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      {
        internalType: 'address payable',
        name: 'withdrawAddress',
        type: 'address',
      },
      { internalType: 'uint256', name: 'amount', type: 'uint256' },
    ],
    name: 'withdrawDepositTo',
    outputs: [],
    stateMutability: 'payable',
    type: 'function',
  },
  { stateMutability: 'payable', type: 'receive' },
] as const

const factoryAbi = [
  {
    inputs: [
      {
        internalType: 'address',
        name: '_basicImplementation',
        type: 'address',
      },
      { internalType: 'address', name: '_newOwner', type: 'address' },
    ],
    stateMutability: 'nonpayable',
    type: 'constructor',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'account',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'initialAuthModule',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'uint256',
        name: 'index',
        type: 'uint256',
      },
    ],
    name: 'AccountCreation',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'account',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'initialAuthModule',
        type: 'address',
      },
    ],
    name: 'AccountCreationWithoutIndex',
    type: 'event',
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: 'address',
        name: 'previousOwner',
        type: 'address',
      },
      {
        indexed: true,
        internalType: 'address',
        name: 'newOwner',
        type: 'address',
      },
    ],
    name: 'OwnershipTransferred',
    type: 'event',
  },
  {
    inputs: [],
    name: 'accountCreationCode',
    outputs: [{ internalType: 'bytes', name: '', type: 'bytes' }],
    stateMutability: 'pure',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'epAddress', type: 'address' },
      { internalType: 'uint32', name: 'unstakeDelaySec', type: 'uint32' },
    ],
    name: 'addStake',
    outputs: [],
    stateMutability: 'payable',
    type: 'function',
  },
  {
    inputs: [],
    name: 'basicImplementation',
    outputs: [{ internalType: 'address', name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'moduleSetupContract', type: 'address' },
      { internalType: 'bytes', name: 'moduleSetupData', type: 'bytes' },
    ],
    name: 'deployAccount',
    outputs: [{ internalType: 'address', name: 'proxy', type: 'address' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'moduleSetupContract', type: 'address' },
      { internalType: 'bytes', name: 'moduleSetupData', type: 'bytes' },
      { internalType: 'uint256', name: 'index', type: 'uint256' },
    ],
    name: 'deployCounterFactualAccount',
    outputs: [{ internalType: 'address', name: 'proxy', type: 'address' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'moduleSetupContract', type: 'address' },
      { internalType: 'bytes', name: 'moduleSetupData', type: 'bytes' },
      { internalType: 'uint256', name: 'index', type: 'uint256' },
    ],
    name: 'getAddressForCounterFactualAccount',
    outputs: [{ internalType: 'address', name: '_account', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'minimalHandler',
    outputs: [
      {
        internalType: 'contract DefaultCallbackHandler',
        name: '',
        type: 'address',
      },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'owner',
    outputs: [{ internalType: 'address', name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'renounceOwnership',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'address', name: 'newOwner', type: 'address' }],
    name: 'transferOwnership',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'address', name: 'epAddress', type: 'address' }],
    name: 'unlockStake',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'epAddress', type: 'address' },
      {
        internalType: 'address payable',
        name: 'withdrawAddress',
        type: 'address',
      },
    ],
    name: 'withdrawStake',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
] as const

import { beforeEach, describe, expect, test, vi } from 'vitest'
import { anvilMainnet } from '../../../../test/src/anvil.js'
import { bundlerMainnet } from '../../../../test/src/bundler.js'
import { accounts } from '../../../../test/src/constants.js'
import { privateKeyToAccount } from '../../../accounts/privateKeyToAccount.js'
import {
  mine,
  sendTransaction,
  verifyMessage,
  writeContract,
} from '../../../actions/index.js'
import {
  encodeFunctionData,
  keccak256,
  parseAbi,
  parseEther,
} from '../../../utils/index.js'
import { estimateUserOperationGas } from '../../actions/bundler/estimateUserOperationGas.js'
import { prepareUserOperation } from '../../actions/bundler/prepareUserOperation.js'
import { sendUserOperation } from '../../actions/bundler/sendUserOperation.js'
import {
  sign,
  toBiconomySmartAccountV2,
  wrapSignature,
} from './toBiconomySmartAccountV2.js'

const client = anvilMainnet.getClient({ account: true })
const bundlerClient = bundlerMainnet.getBundlerClient({ client })

const owner = privateKeyToAccount(accounts[0].privateKey)
const DEFAULT_ECDSA_MODULE_ADDRESS =
  '0x0000001c5b32F37F5beA87BDD5374eB2aC54eA8e'
const message = 'hello world'

describe('return value: encodeCalls', () => {
  test('single', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
    })

    const callData_1 = await account.encodeCalls([
      { to: '0x0000000000000000000000000000000000000000' },
    ])
    const callData_2 = await account.encodeCalls([
      { to: '0x0000000000000000000000000000000000000000', value: 69n },
    ])
    const callData_3 = await account.encodeCalls([
      {
        to: '0x0000000000000000000000000000000000000000',
        value: 69n,
        data: '0xdeadbeef',
      },
    ])

    expect(callData_1).toMatchInlineSnapshot(
      `"0xb61d27f60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000"`,
    )
    expect(callData_2).toMatchInlineSnapshot(
      `"0xb61d27f60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004500000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000"`,
    )
    expect(callData_3).toMatchInlineSnapshot(
      `"0xb61d27f60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004500000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004deadbeef00000000000000000000000000000000000000000000000000000000"`,
    )
  })

  test('batch', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
    })

    const callData = await account.encodeCalls([
      { to: '0x0000000000000000000000000000000000000000' },
      { to: '0x0000000000000000000000000000000000000000', value: 69n },
      {
        to: '0x0000000000000000000000000000000000000000',
        value: 69n,
        data: '0xdeadbeef',
      },
    ])

    expect(callData).toMatchInlineSnapshot(
      `"0x00004680000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045000000000000000000000000000000000000000000000000000000000000004500000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004deadbeef00000000000000000000000000000000000000000000000000000000"`,
    )
  })
})

describe('return value: getAddress', () => {
  test('default', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
    })

    const address = await account.getAddress()

    expect(address).toMatchInlineSnapshot(
      `"0x0788816536DEFa6A14779711c0B08b7f0edFe68b"`,
    )

    const implementation_2 = await toBiconomySmartAccountV2({
      client,
      owner: privateKeyToAccount(accounts[1].privateKey),
    })

    const address_2 = await implementation_2.getAddress()

    expect(address_2).toMatchInlineSnapshot(
      `"0x9d7D81B4eecDf15CEb00bA42284EA36f8BE68B90"`,
    )

    const implementation_3 = await toBiconomySmartAccountV2({
      client,
      owner: privateKeyToAccount(accounts[1].privateKey),
    })

    const address_3 = await implementation_3.getAddress()
    expect(address_3).toMatchInlineSnapshot(
      `"0x9d7D81B4eecDf15CEb00bA42284EA36f8BE68B90"`,
    )

    const implementation_4 = await toBiconomySmartAccountV2({
      client,
      owner: privateKeyToAccount(accounts[1].privateKey),
      nonce: 1n,
    })

    const address_4 = await implementation_4.getAddress()

    expect(address_4).toMatchInlineSnapshot(
      `"0x7cfb07Af979D38c4d178b366469abE1292B91B64"`,
    )

    const implementation_5 = await toBiconomySmartAccountV2({
      address: '0xBb0c1d5E7f530e8e648150fc7Cf30912575523E8',
      client,
      owner,
    })

    const address_5 = implementation_5.address
    expect(address_5).toMatchInlineSnapshot(
      `"0xBb0c1d5E7f530e8e648150fc7Cf30912575523E8"`,
    )
  })
})

describe('return value: getFactoryArgs', () => {
  test('default', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
    })

    const signature = await account.getFactoryArgs()
    expect(signature.factory).toMatchInlineSnapshot(
      `"0x000000a56Aaca3e9a4C479ea6b6CD0DbcB6634F5"`,
    )
    expect(signature.factoryData).toMatchInlineSnapshot(
      `"0xdf20ffbc0000000000000000000000000000001c5b32f37f5bea87bdd5374eb2ac54ea8e0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000242ede3bc0000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000000000"`,
    )
  })
})

describe('return value: getStubSignature', () => {
  test('default: private key', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
    })

    const signature = await account.getStubSignature()
    expect(signature).toMatchInlineSnapshot(
      `"0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000001c5b32f37f5bea87bdd5374eb2ac54ea8e0000000000000000000000000000000000000000000000000000000000000041fffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c00000000000000000000000000000000000000000000000000000000000000"`,
    )
  })
})

describe('return value: getNonce', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date(Date.UTC(2023, 1, 1)))
    return () => {
      vi.useRealTimers()
    }
  })

  test('default', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
    })

    const nonce = await account.getNonce()
    expect(nonce).toMatchInlineSnapshot('30902162761021348478818713600000n')
  })

  test('args: key', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
    })

    const nonce = await account.getNonce({ key: 0n })
    expect(nonce).toMatchInlineSnapshot('0n')
  })
})

describe('return value: userOperation.estimateGas', () => {
  test('default: private key', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
    })

    const request = await account.userOperation?.estimateGas?.({
      callData: '0xdeadbeef',
    })
    expect(request).toMatchInlineSnapshot('undefined')
  })
})

describe('return value: signMessage', () => {
  test('default', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
      nonce: 70n,
    })

    const ecdsaOwnerAddress = owner.address ?? '0x'
    const moduleRegistryParsedAbi = parseAbi([
      'function initForSmartAccount(address owner)',
    ])
    const ecdsaOwnershipInitData = encodeFunctionData({
      abi: moduleRegistryParsedAbi,
      functionName: 'initForSmartAccount',
      args: [ecdsaOwnerAddress],
    })

    await writeContract(client, {
      ...account.factory,
      functionName: 'deployCounterFactualAccount',
      args: [DEFAULT_ECDSA_MODULE_ADDRESS, ecdsaOwnershipInitData, 70n],
    })
    await mine(client, {
      blocks: 1,
    })

    const signature = await account.signMessage({ message })

    const result = await verifyMessage(client, {
      address: await account.getAddress(),
      message,
      signature,
    })

    expect(result).toBeTruthy()
  })

  test('counterfactual', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
      nonce: 141241n,
    })

    const signature = await account.signMessage({ message })

    const result = await verifyMessage(client, {
      address: await account.getAddress(),
      message,
      signature,
    })

    expect(result).toBeTruthy()
  })
})

describe('return value: signUserOperation', () => {
  test('default', async () => {
    const account = await toBiconomySmartAccountV2({
      client,
      owner,
    })

    const signature = await account.signUserOperation({
      callData: '0xdeadbeef',
      callGasLimit: 69n,
      maxFeePerGas: 69n,
      maxPriorityFeePerGas: 69n,
      nonce: 0n,
      preVerificationGas: 69n,
      signature: '0xdeadbeef',
      verificationGasLimit: 69n,
    })

    expect(signature).toMatchInlineSnapshot(
      `"0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000001c5b32f37f5bea87bdd5374eb2ac54ea8e00000000000000000000000000000000000000000000000000000000000000414a9b87fe5b7a163ce08e14f6c804f254c3d7baf4b5babefe2773cd1b580f7eb232a0ceabd123ae8b9f5a07ce1f31101a032eb734b952d0227384c184966e9f2b1b00000000000000000000000000000000000000000000000000000000000000"`,
    )
  })
})

describe('sign', async () => {
  test('private key', async () => {
    const signature = await sign({
      owner,
      hash: keccak256('0xdeadbeef'),
    })
    expect(signature).toMatchInlineSnapshot(
      `"0xa8a8de243232c52140496c6b3e428090a8a944e1da3af2d6873d0f2151aa54b35aa7e59729d04cd6cc405bacc7e5e834ad56a945a1b2570948ba39febdfbdd3c1c"`,
    )
  })

  test('error: incompat account', async () => {
    await expect(() =>
      sign({
        // @ts-expect-error
        owner: { address: '0x', type: 'json-rpc' },
        hash: keccak256('0xdeadbeef'),
      }),
    ).rejects.toMatchInlineSnapshot(`
      [ViemError: \`owner\` does not support raw sign.

      Version: viem@x.y.z]
    `)
  })
})

describe('wrapSignature', () => {
  test('default: private key', async () => {
    expect(
      wrapSignature({
        signature:
          '0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c',
      }),
    ).toMatchInlineSnapshot(
      `"0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000001c5b32f37f5bea87bdd5374eb2ac54ea8e0000000000000000000000000000000000000000000000000000000000000041fffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c00000000000000000000000000000000000000000000000000000000000000"`,
    )
  })
})

describe('smoke', async () => {
  const account = await toBiconomySmartAccountV2({
    client,
    owner,
  })

  await sendTransaction(client, {
    account: owner,
    to: account.address,
    value: parseEther('100'),
  })

  await mine(client, {
    blocks: 1,
  })

  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date(Date.UTC(2023, 1, 1)))
    return () => {
      vi.useRealTimers()
    }
  })

  test('estimateUserOperationGas', async () => {
    const gas = await estimateUserOperationGas(bundlerClient, {
      account,
      calls: [
        {
          to: '0x0000000000000000000000000000000000000000',
        },
      ],
    })

    expect(gas).toMatchInlineSnapshot(`
      {
        "callGasLimit": 80000n,
        "preVerificationGas": 65027n,
        "verificationGasLimit": 387933n,
      }
    `)
  })

  test('prepareUserOperation', async () => {
    const userOperation = await prepareUserOperation(bundlerClient, {
      account,
      calls: [
        {
          to: '0x0000000000000000000000000000000000000000',
        },
      ],
      maxFeePerGas: 22785120848n,
      maxPriorityFeePerGas: 2000000000n,
    })

    expect({ ...userOperation, account: null }).toMatchInlineSnapshot(`
      {
        "account": null,
        "callData": "0xb61d27f60000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000",
        "callGasLimit": 80000n,
        "initCode": "0x000000a56Aaca3e9a4C479ea6b6CD0DbcB6634F5df20ffbc0000000000000000000000000000001c5b32f37f5bea87bdd5374eb2ac54ea8e0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000242ede3bc0000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000000000",
        "maxFeePerGas": 22785120848n,
        "maxPriorityFeePerGas": 2000000000n,
        "nonce": 30902162761039795222892423151616n,
        "paymasterAndData": "0x",
        "paymasterPostOpGasLimit": undefined,
        "paymasterVerificationGasLimit": undefined,
        "preVerificationGas": 65027n,
        "sender": "0x0788816536DEFa6A14779711c0B08b7f0edFe68b",
        "signature": "0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000001c5b32f37f5bea87bdd5374eb2ac54ea8e0000000000000000000000000000000000000000000000000000000000000041fffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c00000000000000000000000000000000000000000000000000000000000000",
        "verificationGasLimit": 387933n,
      }
    `)
  })

  test('sendUserOperation', async () => {
    const hash = await sendUserOperation(bundlerClient, {
      account,
      calls: [
        {
          to: '0x0000000000000000000000000000000000000000',
          value: 1n,
        },
      ],
      callGasLimit: 80000n,
      verificationGasLimit: 369595n,
      preVerificationGas: 67100n,
      maxFeePerGas: 22785120848n,
      maxPriorityFeePerGas: 2000000000n,
    })

    await mine(client, {
      blocks: 1,
    })

    expect(hash).toMatchInlineSnapshot(
      `"0xa81da54eeb429f697a46bec4e19e37d33963324e3ee34a3ca31fd3bd491b6d02"`,
    )
  })
})

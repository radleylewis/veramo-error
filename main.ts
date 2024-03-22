import * as u8a from "uint8arrays";
import { SigningKey } from "ethers";
import { x25519 } from "@noble/curves/ed25519";
import { bytesToHex, concat, hexToBytes } from "@veramo/utils";

import {
  createAgent,
  IDIDManager,
  IResolver,
  IDataStore,
  IDataStoreORM,
  IKeyManager,
  ICredentialPlugin,
  MinimalImportableKey,
  IKey,
} from "@veramo/core";

import { DIDManager } from "@veramo/did-manager";
import { EthrDIDProvider } from "@veramo/did-provider-ethr";
import { KeyManager } from "@veramo/key-manager";
import { KeyManagementSystem, SecretBox } from "@veramo/kms-local";
import { CredentialPlugin } from "@veramo/credential-w3c";
import { DIDResolverPlugin } from "@veramo/did-resolver";
import { Resolver } from "did-resolver";
import { getResolver as ethrDidResolver } from "ethr-did-resolver";

import {
  Entities,
  KeyStore,
  DIDStore,
  PrivateKeyStore,
  migrations,
} from "@veramo/data-store";

import { DataSource } from "typeorm";

// This will be the name for the local sqlite database for demo purposes
const DATABASE_FILE = "database.sqlite";

const LINEA_TESTNET_NAMESPACE = "linea:goerli";

const KMS_SECRET_KEY = process.env.KMS_SECRET_KEY!;

const SEPOLIA_TESTNET_NAMESPACE = "sepolia";
const SEPOLIA_TESTNET_PROVIDER = `did:ethr:${SEPOLIA_TESTNET_NAMESPACE}`;

const dbConnection = new DataSource({
  type: "sqlite",
  database: DATABASE_FILE,
  synchronize: false,
  migrations,
  migrationsRun: true,
  logging: ["error", "info", "warn"],
  entities: Entities,
}).initialize();

export const agent = createAgent<
  IDIDManager &
    IKeyManager &
    IDataStore &
    IDataStoreORM &
    IResolver &
    ICredentialPlugin
>({
  plugins: [
    new KeyManager({
      store: new KeyStore(dbConnection),
      kms: {
        local: new KeyManagementSystem(
          new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY)),
        ),
      },
    }),
    new DIDManager({
      store: new DIDStore(dbConnection),
      // store: new MemoryDIDStore(),
      defaultProvider: SEPOLIA_TESTNET_PROVIDER,
      providers: {
        "did:ethr:sepolia": new EthrDIDProvider({
          defaultKms: "local",
          network: SEPOLIA_TESTNET_NAMESPACE,
          rpcUrl: `https://sepolia.infura.io/v3/${process.env.INFURA_API_KEY}`,
          registry: "0x03d5003bf0e79c5f5223588f347eba39afbc3818",
        }),
      },
    }),
    new DIDResolverPlugin({
      resolver: new Resolver({
        ...ethrDidResolver({
          infuraProjectId: process.env.INFURA_API_KEY,
          networks: [
            {
              name: LINEA_TESTNET_NAMESPACE,
              rpcUrl: `https://linea-goerli.infura.io/v3/${process.env.INFURA_API_KEY}`,
              registry: "0x03d5003bf0e79c5f5223588f347eba39afbc3818",
            },
            {
              name: SEPOLIA_TESTNET_NAMESPACE,
              rpcUrl: `https://sepolia.infura.io/v3/${process.env.INFURA_API_KEY}`,
              registry: "0x03d5003bf0e79c5f5223588f347eba39afbc3818",
            },
          ],
        }),
      }),
    }),
    new CredentialPlugin(),
  ],
});

async function main() {
  const secpKey = secp256FromPrivateKey(
    process.env.WALLET_PRIVATE_KEY!,
    "local",
  );

  const did = buildDid(secpKey);
  await agent.didManagerImport({
    did,
    provider: SEPOLIA_TESTNET_PROVIDER,
    controllerKeyId: secpKey.kid ?? `tspn-owner-key`,
    keys: [secpKey],
  });

  const xKey = generateX25519KeyPair("didcomm-enc-key");

  const isIKey = (key: MinimalImportableKey | IKey): key is IKey => {
    if (!key.privateKeyHex) return false;
    if (!key.publicKeyHex) return false;
    if (!key.kid) return false;
    return true;
  };

  const publicDidDoc = await agent.resolveDid({ didUrl: did });

  console.log("Public DID Doc: ", JSON.stringify(publicDidDoc, null, 2));

  if (!isIKey(xKey)) throw new Error("xKey is not an IKey");
  console.log("ADDING X25519 KEY", xKey);
  await agent.didManagerAddKey({ did, key: xKey });

  const localDid = await agent.didManagerGet({ did });
  console.log("Local DID: ", JSON.stringify(localDid, null, 2));
}

const buildDid = (key: MinimalImportableKey) => {
  const compressedPublicKey = SigningKey.computePublicKey(
    `0x${key.publicKeyHex}`,
    true,
  );
  return `${SEPOLIA_TESTNET_PROVIDER}:${compressedPublicKey}`;
};

function generateX25519KeyPair(
  kid: string = "my-x25519-key",
  secretKeyHex?: string,
): MinimalImportableKey {
  const secretKey = secretKeyHex
    ? hexToBytes(secretKeyHex)
    : x25519.utils.randomPrivateKey();

  function generateX25519KeyPairFromSeed(seed: Uint8Array): {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
  } {
    if (seed.length !== 32) {
      throw new Error(`x25519: seed must be 32 bytes`);
    }
    return {
      publicKey: x25519.getPublicKey(seed),
      privateKey: seed,
    };
  }

  const { privateKey, publicKey } = generateX25519KeyPairFromSeed(secretKey);
  const privateKeyHex = bytesToHex(concat([privateKey, publicKey]));
  const publicKeyHex = bytesToHex(publicKey);

  return {
    kms: "local",
    kid,
    type: "X25519",
    privateKeyHex,
    publicKeyHex,
    meta: { algorithms: ["ECDH", "ECDH-ES", "ECDH-1PU"] },
  } satisfies MinimalImportableKey;
}

function secp256FromPrivateKey(
  privateKeyHex: string,
  kms: string,
  kid?: string,
): MinimalImportableKey {
  const privateBytes = u8a.fromString(privateKeyHex.toLowerCase(), "base16");
  const keyPair = new SigningKey(privateBytes);
  const publicKeyHex = keyPair.publicKey.substring(2);
  return {
    type: "Secp256k1",
    kid: kid ?? publicKeyHex,
    privateKeyHex,
    publicKeyHex,
    kms,
    meta: {
      algorithms: [
        "ES256K",
        "ES256K-R",
        "eth_signTransaction",
        "eth_signTypedData",
        "eth_signMessage",
        "eth_rawSign",
      ],
    },
  };
}

main();

import BN from "bn.js";
import { ec } from "elliptic";
import { Buffer } from "buffer";
import { keccak256 } from "js-sha3";

// elliptic curve
const ecc = ec("secp256k1");
// elliptic curve generator point
const G = ecc.g;

/**
 * It creates a random 77 digit number ie.total amount of digits in 2^256-1 converts it to a string, and returns the first 77 characters of that
 * string
 * @returns A random value
 */
const getRandomValue = () => {
  let randomNum = window.crypto.getRandomValues(new Uint32Array(10));
  let randomValue = randomNum.join("").slice(0, 77);
  return randomValue;
};

/**
 * It takes a string of numbers and converts it to a hexadecimal string
 * @param str - The string to convert to hex.
 * @returns The hexadecimal representation of the number.
 */
const toHex = (str) => {
  let a = new BN(str, 10);
  let b = a.toString(16);
  return b;
};

/**
 * It takes a hexadecimal string and returns a BN object
 * @param hex - The private key in hexadecimal format.
 * @returns A BN object
 */
const getPrivateKey = (hex) => {
  const pk = new BN(hex, 16);
  return pk;
};

/**
 * It takes a private key and returns the public key
 * @param privatekey - The private key of the user.
 * @returns The public key is being returned.
 */
const getPublicKey = (privatekey) => {
  const K = G.mul(privatekey);
  const x = K.getX().toArrayLike(Buffer);
  const y = K.getY().toArrayLike(Buffer);

  let pk = Buffer.concat([x, y]);
  return pk;
};

/**
 * It takes a public key, hashes it with keccak256, and returns the last 20 bytes of the hash
 * @param publicKey - The public key of the user.
 * @returns The Ethereum address of the public key.
 */
const getEthAddress = (publicKey) => {
  const kh = keccak256(publicKey);

  const ethAddress = Buffer.from(kh, "hex").slice(-20).toString("hex");
  return ethAddress;
};

/**
 * It takes an address and a hash, and returns a new address where the case of each letter is
 * determined by the corresponding digit in the hash
 * @param addr - The address to be checked.
 * @param hash - The hash of the transaction.
 * @returns A new address with the checksum applied.
 */
const checkSum = (addr, hash) => {
  let newAddr = "";

  addr.split("").forEach((char, i) => {
    if (/[a-z]/.test(char) && parseInt(hash[i], 16) > 8) {
      newAddr += char.toUpperCase();
    } else {
      newAddr += char;
    }
  });
  return newAddr;
};

/**
 * It takes an Ethereum address and returns a checksummed Ethereum address
 * @param address - The address to be converted to checksum address.
 * @returns The newEthAddress is being returned.
 */
const getCheckSumAddress = (address) => {
  // applying EIP-55 mixed-capitalization checksum
  const checksumHash = keccak256(address);

  const newEthAddress = checkSum(address, checksumHash);
  return newEthAddress;
};

const randomValue = getRandomValue();

const hex = toHex(randomValue);
console.log(hex);

const pk = getPublicKey(hex);
const ethAddr = getEthAddress(pk);

const addr = getCheckSumAddress(ethAddr);
console.log("0x" + addr);

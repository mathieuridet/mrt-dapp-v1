import { ethers } from "ethers";
import * as dotenv from "dotenv";

dotenv.config();

console.log("STAKING_ADDRESS from env:", process.env.STAKING_ADDRESS);

const RPC_URL = process.env.SEPOLIA_RPC_URL;                 
const TOKEN = process.env.TOKEN_ADDRESS;   
const STAKING = process.env.STAKING_ADDRESS; 
const AMOUNT = "100"; // MRT amount to send
let PRIVATE_KEY = process.env.PRIVATE_KEY || "";

if (!RPC_URL) throw new Error("❌ Missing SEPOLIA_RPC_URL in .env");
if (!PRIVATE_KEY) throw new Error("❌ Missing PRIVATE_KEY in .env");
if (!TOKEN) throw new Error("❌ Missing TOKEN_ADDRESS in .env");
if (!STAKING) throw new Error("❌ Missing STAKING_ADDRESS in .env");

// Ensure it starts with 0x
if (!PRIVATE_KEY.startsWith("0x")) {
  PRIVATE_KEY = "0x" + PRIVATE_KEY;
}

const erc20Abi = [
  "function transfer(address to, uint256 amount) returns (bool)",
  "function decimals() view returns (uint8)"
];

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
  const token = new ethers.Contract(TOKEN, erc20Abi, wallet);

  const decimals = await token.decimals();
  const amountWei = ethers.parseUnits(AMOUNT, decimals);

  console.log(`Transferring ${AMOUNT} MRT (${amountWei}) to staking vault: ${STAKING}`);

  const tx = await token.transfer(STAKING, amountWei);
  console.log("Tx sent:", tx.hash);

  const rcpt = await tx.wait();
  console.log("✅ Transfer confirmed in block", rcpt.blockNumber);
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});

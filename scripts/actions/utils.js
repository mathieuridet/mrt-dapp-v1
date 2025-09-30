require("dotenv").config();
const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

const RPC_URL = process.env.RPC_URL || process.env.SEPOLIA_RPC_URL;
if (!RPC_URL) throw new Error("Set RPC_URL in .env");
const PRIVATE_KEY = process.env.PRIVATE_KEY;
if (!PRIVATE_KEY) throw new Error("Set PRIVATE_KEY in .env");
const NFT_ADDRESS = process.env.NFT_ADDRESS;

const provider = new ethers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

function loadAbi(artifactRelPath) {
  const artifactPath = path.resolve(__dirname, "../../", artifactRelPath);
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  return artifact.abi;
}

function getNft() {
  if (!NFT_ADDRESS) throw new Error("Set NFT_ADDRESS in .env");
  const abi = loadAbi("artifacts/contracts/MRTNFToken.sol/MRTNFToken.json");
  return new ethers.Contract(NFT_ADDRESS, abi, wallet);
}

module.exports = { ethers, provider, wallet, getNft };

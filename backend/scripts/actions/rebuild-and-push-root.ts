// scripts/rebuild-and-push-root.ts
// Rebuilds the Merkle file from the last hour of NFT mints,
// writes ./frontend/public/claims/current.json,
// and updates the HourlyMerkleDistributor root on-chain if it changed.

import { ethers } from "hardhat";
import fs from "node:fs";
import { MerkleTree } from "merkletreejs";
import keccak256 from "keccak256";

const NFT_ADDRESS = process.env.NFT_ADDRESS!;               
const DISTRIBUTOR = process.env.DISTRIBUTOR_ADDRESS!;      
const OUTPUT = "./frontend/public/claims/current.json";

// ~Sepolia 12s blocks → ~300 blocks/hour. You can tweak this.
const BLOCKS_PER_HOUR = Number(process.env.BLOCKS_PER_HOUR || 300);

function toBuf(hex: string) {
  return Buffer.from(hex.slice(2), "hex");
}

function leafHash(account: `0x${string}`, amount: bigint, round: bigint) {
  return ethers.keccak256(
    ethers.solidityPacked(["address", "uint256", "uint64"], [account, amount, round])
  );
}

async function main() {
  if (!NFT_ADDRESS || !DISTRIBUTOR) {
    throw new Error("Set NFT_ADDRESS and DISTRIBUTOR_ADDRESS in your env");
  }

  const provider = ethers.provider;
  const net = await provider.getNetwork();
  console.log("Chain:", net.name, net.chainId.toString());
  console.log("NFT:", NFT_ADDRESS);
  console.log("Distributor:", DISTRIBUTOR);

  // Attach to distributor to read reward amount and token address
  const dist = await ethers.getContractAt(
    [
      "function token() view returns (address)",
      "function merkleRoot() view returns (bytes32)",
      "function round() view returns (uint64)",
      "function rewardAmount() view returns (uint256)",
      "function setRoot(bytes32,uint64) external",
    ],
    DISTRIBUTOR
  );

  const [tokenAddr, onchainRoot, onchainRound, rewardAmount] = await Promise.all([
    dist.token(),
    dist.merkleRoot(),
    dist.round(),
    dist.rewardAmount(),
  ]);

  console.log("On-chain → root:", onchainRoot);
  console.log("On-chain → round:", onchainRound.toString());
  console.log("On-chain → rewardAmount (wei):", rewardAmount.toString());

  // Fetch ERC721 Transfer (mint) logs for the last hour
  const TRANSFER_SIG = ethers.id("Transfer(address,address,uint256)");
  const ZERO_32 = "0x" + "00".repeat(32);

  const toBlock = await provider.getBlockNumber();
  const fromBlock = Math.max(0, toBlock - BLOCKS_PER_HOUR);

  console.log(`Scanning mints from block ${fromBlock} to ${toBlock} ...`);

  const logs = await provider.getLogs({
    address: NFT_ADDRESS,
    fromBlock,
    toBlock,
    topics: [TRANSFER_SIG, ZERO_32], // indexed "from" == zero → mint
  });

  // Collect unique "to" addresses
  const addrs = new Set<string>();
  for (const log of logs) {
    // topics[2] is indexed "to" (32-byte)
    const to = ethers.getAddress(("0x" + log.topics[2].slice(26)) as `0x${string}`);
    addrs.add(to.toLowerCase());
  }

  // Round = current hour bucket
  const round = BigInt(Math.floor(Date.now() / 1000 / 3600));
  console.log("Round:", round.toString(), "| minters last hour:", addrs.size);

  // Build Merkle tree (sorted pairs), amount = rewardAmount from contract
  const addresses = Array.from(addrs).sort();
  const leaves = addresses.map((a) => toBuf(leafHash(a as `0x${string}`, rewardAmount, round)));

  if (leaves.length === 0) {
    const emptyRoot = ("0x" + "00".repeat(64)) as `0x${string}`;
    const payload = { round: Number(round), root: emptyRoot, claims: [] };
    fs.mkdirSync("./frontend/public/claims", { recursive: true });
    fs.writeFileSync(OUTPUT, JSON.stringify(payload, null, 2));
    console.log("No minters in the last hour. Wrote empty current.json and SKIPPED setRoot.");
    return; // ← very important
  }

  const tree = new MerkleTree(leaves, keccak256, { sortPairs: true });
  const root = ("0x" + tree.getRoot().toString("hex")) as `0x${string}`;

  // Build claims with proofs
  const claims = addresses.map((account, i) => ({
    account,
    amount: rewardAmount.toString(),
    proof: tree.getHexProof(leaves[i]) as `0x${string}`[],
  }));

  // Write JSON for the frontend
  fs.mkdirSync("./frontend/public/claims", { recursive: true });
  const payload = { round: Number(round), root, claims };
  fs.writeFileSync(OUTPUT, JSON.stringify(payload, null, 2));
  console.log("Wrote:", OUTPUT);
  console.log("File root:", root);

  // If root or round changed, push on-chain
  const needUpdate = root.toLowerCase() !== onchainRoot.toLowerCase() || round > onchainRound;
  if (!needUpdate) {
    console.log("No update needed (root/round unchanged).");
    return;
  }

  console.log("Updating distributor setRoot(root, round) ...");
  const tx = await dist.setRoot(root, round);
  console.log("Tx:", tx.hash);
  await tx.wait();
  console.log("Updated. New on-chain root:", await dist.merkleRoot(), "round:", (await dist.round()).toString());

  // Optional: show distributor token balance
  const erc20 = await ethers.getContractAt(
    ["function balanceOf(address) view returns (uint256)", "function decimals() view returns (uint8)"],
    tokenAddr
  );
  const [dec, bal] = await Promise.all([erc20.decimals(), erc20.balanceOf(DISTRIBUTOR)]);
  console.log("Distributor balance:", ethers.formatUnits(bal, dec));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

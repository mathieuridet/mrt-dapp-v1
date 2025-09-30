import { ethers } from "hardhat";
import fs from "node:fs";

async function main() {
  const owner = (await ethers.getSigners())[0].address;
  const TOKEN = process.env.TOKEN_ADDRESS!;
  const rewardHuman = process.env.REWARD_AMOUNT || "5";
  const amount = ethers.parseUnits(rewardHuman, 18);
  const F = await ethers.getContractFactory("MerkleDistributor");
  const c = await F.deploy(owner, TOKEN, amount);
  await c.waitForDeployment();
  console.log("MerkleDistributor:", await c.getAddress());
}

main().catch((e) => { console.error(e); process.exit(1); });

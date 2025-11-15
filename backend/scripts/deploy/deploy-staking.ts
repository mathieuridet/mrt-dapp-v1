import { ethers, network } from "hardhat";

// How many tokens per hour to emit (as a decimal string)
const TOKENS_PER_HOUR = "2.0";
const DECIMALS = 18;

// Convert to “tokens per second” in wei (bigint)
const REWARD_RATE = (() => {
  const perHourWei = ethers.parseUnits(TOKENS_PER_HOUR, DECIMALS);
  return perHourWei / 3600n;
})();

async function main() {
  const owner = (await ethers.getSigners())[0].address;
  const TOKEN = process.env.TOKEN_ADDRESS!;

  console.log("Deploying to:", network.name);

  const F = await ethers.getContractFactory("SimpleStakingVault");
  const c = await F.deploy(owner, TOKEN, REWARD_RATE);
  await c.waitForDeployment();
  console.log("SimpleStakingVault:", await c.getAddress());
  console.log("Reward rate (wei/sec):", REWARD_RATE.toString());
}
main().catch((e) => { console.error(e); process.exit(1); });

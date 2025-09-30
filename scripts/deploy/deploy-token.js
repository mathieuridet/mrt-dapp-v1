const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();

  const MRToken = await ethers.getContractFactory("MRToken");
  const mrToken = await MRToken.deploy(deployer.address);

  await mrToken.waitForDeployment();

  console.log("MRToken deployed to:", await mrToken.getAddress());
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

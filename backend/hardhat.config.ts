require("dotenv").config();
require("@nomicfoundation/hardhat-toolbox");
require("hardhat-abi-exporter");

module.exports = {
  solidity: { version: "0.8.24", settings: { optimizer: { enabled: true, runs: 200 } } },
  networks: {
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    polygon_amoy: {
      url: process.env.AMOY_RPC_URL || "https://rpc-amoy.polygon.technology",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
      chainId: 80002,
    },
  },
  etherscan: { apiKey: process.env.ETHERSCAN_API_KEY },
  abiExporter: [{
    path: "../frontend/abi",
    runOnCompile: true,
    clear: true,
    flat: true,
    only: ["MRTNFToken", "MRToken", "HourlyMerkleDistributor", "SimpleStakingVault"],
    format: "json"
  }],
};
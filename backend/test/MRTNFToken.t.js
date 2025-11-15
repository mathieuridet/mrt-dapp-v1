const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

async function deployFixture() {
  const [owner, user, other] = await ethers.getSigners();

  const baseURI = "ipfs://QmTestMetadataCID/";
  const maxSupply = 3;                 
  const mintPriceWei = ethers.parseEther("0.02");
  const royaltyBps = 500;                      

  const NFT = await ethers.getContractFactory("contracts/MRTNFToken.sol:MRTNFToken");
  const nft = await NFT.deploy(
    owner.address,
    baseURI,
    maxSupply,
    mintPriceWei,
    owner.address,
    royaltyBps
  );
  await nft.waitForDeployment();

  return { nft, owner, user, other, baseURI, maxSupply, mintPriceWei, royaltyBps };
}

describe("MRTNFToken", function () {
  it("deploys with correct params", async () => {
    const {nft, owner, maxSupply, mintPriceWei} = await loadFixture(deployFixture);
    expect(await nft.owner()).to.equals(owner.address);
    expect(await nft.MAX_SUPPLY()).to.equals(maxSupply);
    expect(await nft.mintPrice()).to.equals(mintPriceWei);
    expect(await nft.saleActive()).to.equals(true);
  });

  it("mints when sale is active and updates totalSupply & ownership", async () => {
    const {nft, user, mintPriceWei} = await loadFixture(deployFixture);
    await expect(nft.connect(user).mint(1, {value: mintPriceWei}))
      .to.emit(nft, "Transfer")
      .withArgs(ethers.ZeroAddress, user.address, 1n);

    expect(await nft.totalSupply()).to.equals(1);
    expect(await nft.ownerOf(1n)).to.equals(user.address);
  });

  it("reverts when sale is not active", async () => {
    const {nft, user, mintPriceWei} = await loadFixture(deployFixture);
    await nft.setSaleActive(false); 
    await expect(nft.connect(user).mint(1, {value: mintPriceWei}))
      .to.be.revertedWithCustomError(nft, "EnforcedPause");
  });

  it("reverts on insufficient ETH", async () => {
    const {nft, user, mintPriceWei} = await loadFixture(deployFixture);
    await expect(nft.connect(user).mint(1, {value: mintPriceWei - 1n}))
      .to.be.revertedWith("INSUFFICIENT_ETH")
  });

  it("refunds excess ETH (contract keeps only mintPrice * qty)", async () => {
    const {nft, user, mintPriceWei} = await loadFixture(deployFixture);

    const provider = ethers.provider;
    const before = await provider.getBalance(await nft.getAddress());

    const extra = ethers.parseEther("0.005");
    const value = mintPriceWei + extra;

    const tx = await nft.connect(user).mint(1n, { value });
    await tx.wait();

    const after = await provider.getBalance(await nft.getAddress());
    expect(after - before).to.equals(mintPriceWei);
  });

  it("enforces MAX_SUPPLY", async () => {
    const {nft, user, maxSupply, mintPriceWei} = await loadFixture(deployFixture);

    for(let i = 0; i < maxSupply; i++) {
      await nft.connect(user).mint(1, { value: mintPriceWei });
    }
    expect(await nft.totalSupply()).to.equals(BigInt(maxSupply));

    await expect(nft.connect(user).mint(1, { value: mintPriceWei }))
      .to.be.revertedWith("MAX_SUPPLY");
  });

  it("tokenURI uses baseURI + id + .json", async () => {
    const {nft, user, mintPriceWei, baseURI} = await loadFixture(deployFixture);
    await nft.connect(user).mint(1, { value: mintPriceWei });

    const uri = await nft.tokenURI(1);
    expect(uri).to.equals(`${baseURI}1.json`);
  });

  it("only owner can setBaseURI", async () => {
    const {nft, owner, user} = await loadFixture(deployFixture);
    await expect(nft.connect(user).setBaseURI("ipfs://new/")).to.be.revertedWithCustomError(nft, "OwnableUnauthorizedAccount");
    await nft.connect(owner).setBaseURI("ipfs://new/");
    // spot-check via tokenURI after mint
    await nft.connect(user).mint(1, { value: await nft.mintPrice() });
    expect(await nft.tokenURI(1)).to.equal("ipfs://new/1.json");
  });

  if("withdraw sends contract balance to owner", async () => {
    const {nft, owner, user, mintPriceWei} = await loadFixture(deployFixture);

    await nft.connect(user).mint(2, { value: mintPriceWei * 2n});
    
    const provider = ethers.provider;
    const contractAddr = await nft.getAddress();
    const beforeContract = await provider.getBalance(contractAddr);
    expect(beforeContract).to.equals(mintPriceWei * 2n);

    const beforeOwner = await provider.getBalance(owner.address);
    const tx = await nft.connect(owner).withdraw(owner.address);
    const rc = await tx.wait();

    const afterContract = await provider.getBalance(contractAddr);
    const afterOwner = await provider.getBalance(owner.address);

    expect(afterContract).to.equals(0n);
    expect(afterOwner).to.be.greaterThan(beforeOwner);
  });

  it("royaltyInfo returns receiver and correct amount", async () => {
    const { nft, owner } = await loadFixture(deployFixture);

    const salePrice = ethers.parseEther("1");
    const [receiver, amount] = await nft.royaltyInfo(1, salePrice);

    expect(receiver).to.equals(owner.address);
    expect(amount).to.equals(salePrice * 500n / 10000n);
  });

   it("enforces 1 mint per wallet per hour", async () => {
    const { nft, user, mintPriceWei } = await loadFixture(deployFixture);

    // First mint works
    await expect(nft.connect(user).mint(1, { value: mintPriceWei }))
      .to.emit(nft, "Transfer");

    // Immediate second mint should revert
    await expect(nft.connect(user).mint(1, { value: mintPriceWei }))
      .to.be.revertedWith("MINT_TOO_SOON");

    // Fast forward 1 hour
    await ethers.provider.send("evm_increaseTime", [3600]); // add 3600 seconds
    await ethers.provider.send("evm_mine", []);             // mine a block

    // Now it works again
    await expect(nft.connect(user).mint(1, { value: mintPriceWei }))
      .to.emit(nft, "Transfer");
  });

});
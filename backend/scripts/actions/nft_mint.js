const { ethers, provider, wallet, getNft } = require("./utils");

(async () => {
  const nft = getNft();

  const qty = BigInt(process.argv[2] || "1");
  const price = await nft.mintPrice();
  const overpay = process.env.OVERPAY_ETH ? ethers.parseEther(process.env.OVERPAY_ETH) : 0n;
  const value = price * qty + overpay;

  console.log(`Minting ${qty} from ${wallet.address} with value ${value} wei`);

  const before = await provider.getBalance(await nft.getAddress());
  const tx = await nft.mint(qty, { value });
  console.log("tx:", tx.hash);
  const rc = await tx.wait();
  console.log("status:", rc.status, "gasUsed:", rc.gasUsed.toString());

  const after = await provider.getBalance(await nft.getAddress());
  console.log("contract balance delta:", (after - before).toString(), "wei");
})();

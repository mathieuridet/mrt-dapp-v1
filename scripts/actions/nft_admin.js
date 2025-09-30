const { ethers, getNft, wallet } = require("./utils");

(async () => {
  const nft = getNft();
  const cmd = (process.argv[2] || "").toLowerCase();

  if (cmd === "sale") {
    const active = (process.argv[3] || "").toLowerCase() === "true";
    // Try setSaleActive(bool) first; if not present, fall back to pause/unpause
    try {
      const tx = await nft.setSaleActive(active);
      console.log("setSaleActive tx:", tx.hash);
      await tx.wait();
    } catch {
      const paused = await nft.paused();
      const tx = active ? await nft.unpause() : await nft.pause();
      console.log((active ? "unpause" : "pause") + " tx:", tx.hash);
      await tx.wait();
    }
  } else if (cmd === "baseuri") {
    const uri = process.argv[3];
    if (!uri) throw new Error("Usage: node scripts/node/nft_admin.js baseuri ipfs://CID/");
    const tx = await nft.setBaseURI(uri);
    console.log("setBaseURI tx:", tx.hash);
    await tx.wait();
  } else if (cmd === "withdraw") {
    const to = process.argv[3] || wallet.address;
    const tx = await nft.withdraw(to);
    console.log("withdraw tx:", tx.hash);
    await tx.wait();
  } else if (cmd === "royalty") {
    const saleEth = process.argv[3] || "1";
    const saleWei = ethers.parseEther(saleEth);
    const [receiver, amount] = await nft.royaltyInfo(1, saleWei);
    console.log("royaltyInfo(1,", saleWei.toString(), ") ->", { receiver, amount: amount.toString() });
  } else {
    console.log(`Usage:
  node scripts/node/nft_admin.js sale <true|false>
  node scripts/node/nft_admin.js baseuri <ipfs://CID/>
  node scripts/node/nft_admin.js withdraw [to]
  node scripts/node/nft_admin.js royalty [saleEth]`);
  }
})();

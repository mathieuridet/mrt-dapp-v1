const { ethers, getNft } = require("./utils");

(async () => {
  const nft = getNft();

  const [name, symbol, maxSupply, mintPrice, totalSupply] = await Promise.all([
    nft.name(),
    nft.symbol(),
    nft.MAX_SUPPLY(),
    nft.mintPrice(),
    nft.totalSupply(),
  ]);

  // Detect saleActive (supports either boolean gate or Pausable)
  let saleActive = null;
  try { saleActive = await nft.saleActive(); } catch {}
  if (saleActive === null) {
    try { saleActive = !(await nft.paused()); } catch {}
  }

  console.log({
    name, symbol,
    maxSupply: maxSupply.toString(),
    mintPriceWei: mintPrice.toString(),
    saleActive,
    totalSupply: totalSupply.toString(),
  });

  // tokenURI (defaults to id=1)
  const id = BigInt(process.argv[2] || "1");
  try {
    const uri = await nft.tokenURI(id);
    console.log(`tokenURI(${id}) = ${uri}`);
  } catch (e) {
    console.log(`tokenURI(${id}) failed:`, e.shortMessage || e.message);
  }
})();

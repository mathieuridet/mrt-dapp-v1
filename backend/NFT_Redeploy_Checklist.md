# MRTNFT Redeploy Checklist ✅

This file is a step-by-step guide for redeploying the MRTNFT contract when updating rules (e.g. mint limit) or assets (images/metadata).

---

## 1. Assets
- [ ] Upload new `/images` folder to IPFS (Pinata, NFT.storage, etc.).
- [ ] Copy the new `CID`.
- [ ] Update `/metadata` JSON files to reference `ipfs://<imagesCID>/filename.png`.
- [ ] Upload `/metadata` folder to IPFS.
- [ ] Copy the new metadata `CID` → this becomes the `baseURI`.

---

## 2. Contract
- [ ] Update `baseURI` in the deploy script:
  ```js
  const baseURI = "ipfs://<metadataCID>/";
  ```
- [ ] Deploy the contract with Hardhat/Foundry.
  ```bash
  cd backend
  npx hardhat run scripts/deploy/deploy-nft.js --network sepolia
  ```
- [ ] Verify the contract on Etherscan:
  ```bash
  cd backend
  npx hardhat verify --network sepolia <contractAddress> <ownerAddress> "ipfs://<metadataCID>/" <maxSupply> <mintPriceInWei:2000000000000000000> <royaltyReceiver> <royaltyBps:500>
  ```
- Regenerate the ABI:
  Execute the following in backend folder
  ```bash
  cd backend
  npx hardhat compile
  cp artifacts/contracts/nft/MRTNFToken.sol/MRTNFToken.json ../frontend/abi/MRTNFToken.json
  ``` 
- [ ] Note the new contract address.

---

## 3. Frontend / Env Vars
- [ ] Update `.env.local`:
  ```bash
  NEXT_PUBLIC_NFT_ADDRESS=0xYourNewContract
  ```
- [ ] Update `.env.production` (Vercel → Project Settings → Environment Variables).
- [ ] Commit & push to redeploy the frontend.

---

## 4. Backend / Merkle Builder
- [ ] Update `NEXT_PUBLIC_NFT_ADDRESS` in:
  - GitHub Actions workflow vars (`vars` section).
  - Vercel env vars (`NEXT_PUBLIC_NFT_ADDRESS`).
- [ ] Redeploy or trigger rebuild workflow.

---

## 5. Alchemy Webhook
- [ ] Update webhook content by replacing the address with the new one
- [ ] Update `ALCHEMY_SIGNING_KEY` in Vercel env vars



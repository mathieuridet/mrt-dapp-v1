// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Royalty.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract MRTNFToken is ERC721Royalty, Ownable, ReentrancyGuard, Pausable {
    // --- Config (immutable after deploy) ---
    uint256 public immutable MAX_SUPPLY;                // hard cap on total mints
    uint256 public immutable mintPrice;                 // price per NFT in wei
    string  private _baseTokenURI;                      // IPFS folder, e.g. "ipfs://QmCID/"


    // --- State ---
    uint256 private _nextId = 1;
    bool public saleActive = true;

    // --- Mint cooldown ---
    uint256 public constant MINT_INTERVAL = 1 hours;
    mapping(address => uint256) public lastMint; // wallet → last timestamp

    event SaleActiveSet(bool active);

    constructor(address initialOwner, 
                string memory baseURI,
                uint256 maxSupply,
                uint256 mintPriceWei,
                address royaltyReceiver, 
                uint96 royaltyBps)
        ERC721("MRTNFToken", "MRTNFT")
        Ownable(initialOwner)
    {
        require(maxSupply > 0, "MAX_SUPPLY_ZERO");          
        require(bytes(baseURI).length > 0, "BASE_URI_EMPTY");           
        require(royaltyReceiver != address(0), "ROYALTY_RECEIVER_0");  
        require(royaltyBps > 0, "ROYALTY_BPS_0");                 

        MAX_SUPPLY = maxSupply;
        mintPrice  = mintPriceWei;
        _baseTokenURI = baseURI;

        _setDefaultRoyalty(royaltyReceiver, royaltyBps);
    }

    // Allow user to mint a token (pay exact amount)
    function mint(uint256 quantity) external payable whenNotPaused nonReentrant {
        require(quantity > 0, "QTY_ZERO");
        require(totalSupply() + quantity <= MAX_SUPPLY, "MAX_SUPPLY");
        uint256 cost = mintPrice * quantity;        
        require(msg.value >= cost, "INSUFFICIENT_ETH");

        // enforce cooldown
        require(block.timestamp >= lastMint[msg.sender] + MINT_INTERVAL, "MINT_TOO_SOON");

        for (uint256 i = 0; i < quantity; i++) {
            _safeMint(msg.sender, _nextId++);
        }

        // update last mint timestamp for this wallet
        lastMint[msg.sender] = block.timestamp;

        uint256 refund = msg.value - cost;
        if (refund > 0) {
            (bool ok, ) = msg.sender.call{value: refund}("");
            if (!ok) {
                // refund failed — do NOT revert
                // the extra ETH remains in this contract; owner can withdraw later
            }
        }
    }


    // --- Owner tools ---
    function setBaseURI(string calldata newBaseURI) external onlyOwner {
        _baseTokenURI = newBaseURI;
    }

    // Allow owner to change the default royalty
    function setDefaultRoyalty(address receiver, uint96 bps) external onlyOwner {
        _setDefaultRoyalty(receiver, bps);
    }

    // Allow owner to delete the default royalty
    function deleteDefaultRoyalty() external onlyOwner {
        _deleteDefaultRoyalty();
    }

    // Allow owner to withdraw
    function withdraw(address payable to) external onlyOwner {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "WITHDRAW_FAILED");
    }

    // Allow the owner to set the token in sale or not
    function setSaleActive(bool active) external onlyOwner {
        active ? _unpause() : _pause();
    }


    // --- Views ---
    function totalSupply() public view returns (uint256) {
        return _nextId - 1;
    }

    function _baseURI() internal view override returns (string memory) {
        return _baseTokenURI;
    }

    // Append ".json" to files names
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        return string.concat(super.tokenURI(tokenId), ".json");
    }


    // --- Interfaces ---
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Royalty)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}

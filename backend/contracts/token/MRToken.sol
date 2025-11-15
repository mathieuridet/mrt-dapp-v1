// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";

contract MRToken is ERC20, Ownable, ERC20Permit, ERC20Capped {
    constructor(address initialOwner) ERC20("MRToken", "MRT") ERC20Permit("MRToken") Ownable(initialOwner) ERC20Capped(1_000_000 * 10 ** 18) {
        _mint(msg.sender, 1000 * 10 ** 18);
    }

    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Capped) {
        super._update(from, to, value);
    }

    function mint(address _to, uint256 _amount) public onlyOwner {
        _mint(_to, _amount);
    }
}
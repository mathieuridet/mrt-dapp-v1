# High Impact Findings

## Controlled Delegatecall
- Contract: src/VulnerableContract.sol
- Locations:
  - src/VulnerableContract.sol:8 (element: callContract)
  - src/VulnerableContract.sol:9 (element: (success,None) = yourAddress.delegatecall(abi.encodeWithSignature(doSomething())))
- Confidence: Medium
- Issue: Uses `delegatecall` to an input-controlled target, executing code in the caller’s context.
- Recommendation: Avoid `delegatecall` to untrusted targets; restrict to immutable/whitelisted addresses or replace with interface calls.
- **SWC:** SWC-112: Delegatecall to Untrusted Callee
- **SWC Remediation:** Use `delegatecall` with caution and make sure to never call into untrusted contracts. If the target address is derived from user input ensure to check it against a whitelist of trusted contracts.

# Medium Impact Findings

## Reentrancy (no ETH)
- Contract: src/VulnerableContract.sol
- Locations:
  - src/VulnerableContract.sol:18 (element: callContractAgain)
  - src/VulnerableContract.sol:20 (element: (success,None) = yourAddress.call(abi.encodeWithSelector(selector)))
  - src/VulnerableContract.sol:25 (element: s_otherVar = 0)
- Confidence: Medium
- Issue: External call occurs before a state write, enabling reentrancy before effects are applied. A state variable is written after an external call.
- Recommendation: Apply Checks–Effects–Interactions and/or a reentrancy guard; validate/limit the callee.
- **SWC:** SWC-107: Reentrancy
- **SWC Remediation:** The best practices to avoid Reentrancy weaknesses are: 


- Make sure all internal state changes are performed before the call is executed. This is known as the [Checks-Effects-Interactions pattern](https://solidity.readthedocs.io/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)
- Use a reentrancy lock (ie.  [OpenZeppelin's ReentrancyGuard](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuard.sol).

# Low Impact Findings

## Reentrancy (benign)
- Contract: src/VulnerableContract.sol
- Locations:
  - src/VulnerableContract.sol:8 (element: callContract)
  - src/VulnerableContract.sol:9 (element: (success,None) = yourAddress.delegatecall(abi.encodeWithSignature(doSomething())))
  - src/VulnerableContract.sol:14 (element: s_variable = 0)
- Confidence: Medium
- Issue: External call followed by a state write (marked benign by Slither for this context). A state variable is written after an external call.
- Recommendation: Prefer CEI or a guard if the function can be externally triggered.
- **SWC:** SWC-107: Reentrancy
- **SWC Remediation:** The best practices to avoid Reentrancy weaknesses are: 


- Make sure all internal state changes are performed before the call is executed. This is known as the [Checks-Effects-Interactions pattern](https://solidity.readthedocs.io/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)
- Use a reentrancy lock (ie.  [OpenZeppelin's ReentrancyGuard](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuard.sol).

## Missing zero-check (address)
- Contract: src/VulnerableContract.sol
- Locations:
  - src/VulnerableContract.sol:8 (element: yourAddress)
  - src/VulnerableContract.sol:9 (element: (success,None) = yourAddress.delegatecall(abi.encodeWithSignature(doSomething())))
  - src/VulnerableContract.sol:18 (element: yourAddress)
  - src/VulnerableContract.sol:20 (element: (success,None) = yourAddress.call(abi.encodeWithSelector(selector)))
- Confidence: Medium
- Issue: Target address parameter lacks a `!= address(0)` validation.
- Recommendation: Validate non-zero addresses and check `success` for low-level calls.


# Informational Impact Findings

## Low-level calls
- Contract: src/VulnerableContract.sol
- Locations:
  - src/VulnerableContract.sol:18 (element: callContractAgain)
  - src/VulnerableContract.sol:20 (element: (success,None) = yourAddress.call(abi.encodeWithSelector(selector)))
- Confidence: High
- Issue: Uses low-level calls (`call`/`delegatecall`) that bypass type safety and can fail silently.
- Recommendation: Prefer typed interface calls; if using low-level calls, check `success` and handle returned data.
- **SWC:** SWC-104: Unchecked Call Return Value
- **SWC Remediation:** If you choose to use low-level call methods, make sure to handle the possibility that the call will fail by checking the return value.

## Low-level calls
- Contract: src/VulnerableContract.sol
- Locations:
  - src/VulnerableContract.sol:8 (element: callContract)
  - src/VulnerableContract.sol:9 (element: (success,None) = yourAddress.delegatecall(abi.encodeWithSignature(doSomething())))
- Confidence: High
- Issue: Uses low-level calls (`call`/`delegatecall`) that bypass type safety and can fail silently.
- Recommendation: Prefer typed interface calls; if using low-level calls, check `success` and handle returned data.
- **SWC:** SWC-104: Unchecked Call Return Value
- **SWC Remediation:** If you choose to use low-level call methods, make sure to handle the possibility that the call will fail by checking the return value.

## Naming convention
- Contract: src/VulnerableContract.sol
- Element: `s_variable` (line 5)
- Confidence: High
- Issue: Variable is not in mixedCase.
- Recommendation: Rename variables to mixedCase (e.g., `sVariable`, `sOtherVar`).


## Naming convention
- Contract: src/VulnerableContract.sol
- Element: `s_otherVar` (line 6)
- Confidence: High
- Issue: Variable is not in mixedCase.
- Recommendation: Rename variables to mixedCase (e.g., `sVariable`, `sOtherVar`).


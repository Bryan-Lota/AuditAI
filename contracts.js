// Sample vulnerable Solidity contracts + pre-computed Slither findings for the demo.
// Slither findings match the real Slither JSON schema (detector, impact, confidence, etc.)

window.SAMPLE_CONTRACTS = [
  {
    id: "vault",
    name: "EtherVault.sol",
    title: "Reentrancy + Missing Access Control",
    blurb: "A simple deposit/withdraw vault. Classic reentrancy + privileged function exposure.",
    severity: "critical",
    loc: 38,
    source: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EtherVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");

        // VULN: external call before state update
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] -= amount;
    }

    // VULN: no access control on critical setter
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function emergencyDrain(address payable to) external {
        require(msg.sender == owner, "not owner");
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}`,
    findings: [
      {
        id: "reentrancy-eth",
        check: "reentrancy-eth",
        impact: "High",
        confidence: "Medium",
        title: "Reentrancy in EtherVault.withdraw(uint256)",
        location: "withdraw(uint256)",
        lines: [16, 17, 18, 19, 20, 21],
        description:
          "Reentrancy in EtherVault.withdraw(uint256): External calls before state update at line 18 — `msg.sender.call{value: amount}(\"\")` — can re-enter `withdraw()` before `balances[msg.sender]` is decremented.",
      },
      {
        id: "access-control",
        check: "missing-access-control",
        impact: "Critical",
        confidence: "High",
        title: "Unprotected ownership transfer in setOwner(address)",
        location: "setOwner(address)",
        lines: [25, 26, 27],
        description:
          "Function `setOwner` modifies the `owner` state variable without any access control — anyone can become the contract owner and trigger `emergencyDrain`.",
      },
      {
        id: "low-level-call",
        check: "low-level-calls",
        impact: "Informational",
        confidence: "High",
        title: "Low-level call used in withdraw",
        location: "withdraw(uint256)",
        lines: [18],
        description:
          "Low-level call `msg.sender.call{value: amount}(\"\")` bypasses Solidity's type checking. Acceptable here for variable gas forwarding, but flagged for review.",
      },
    ],
  },
  {
    id: "token",
    name: "MintableToken.sol",
    title: "Integer Overflow + tx.origin Auth",
    blurb: "Older-style ERC20-like token. Unchecked arithmetic and tx.origin authentication.",
    severity: "high",
    loc: 44,
    source: `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract MintableToken {
    string public name = "Demo";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public admin;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() {
        admin = msg.sender;
    }

    // VULN: tx.origin authentication
    modifier onlyAdmin() {
        require(tx.origin == admin, "not admin");
        _;
    }

    function mint(address to, uint256 amount) external onlyAdmin {
        // VULN: unchecked arithmetic, no SafeMath
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        // VULN: silent underflow on insufficient balance
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}`,
    findings: [
      {
        id: "tx-origin",
        check: "tx-origin",
        impact: "High",
        confidence: "Medium",
        title: "Dangerous tx.origin usage in onlyAdmin modifier",
        location: "onlyAdmin (modifier)",
        lines: [17, 18, 19, 20],
        description:
          "Authentication uses `tx.origin` instead of `msg.sender`. A malicious contract can trick the admin into calling it, then call back into `mint()` as the admin.",
      },
      {
        id: "integer-overflow",
        check: "integer-overflow",
        impact: "High",
        confidence: "High",
        title: "Unchecked arithmetic in mint and transfer",
        location: "mint(address,uint256), transfer(address,uint256)",
        lines: [23, 24, 25, 30, 31, 32],
        description:
          "Solidity 0.7.6 does not check arithmetic by default. `totalSupply += amount` and `balanceOf[msg.sender] -= amount` can overflow/underflow silently.",
      },
      {
        id: "missing-zero-check",
        check: "missing-zero-check",
        impact: "Low",
        confidence: "High",
        title: "Missing zero-address check in transfer",
        location: "transfer(address,uint256)",
        lines: [29, 30, 31, 32, 33],
        description:
          "`transfer()` does not validate that `to` is not the zero address. Tokens sent to address(0) become permanently unrecoverable.",
      },
    ],
  },
  {
    id: "auction",
    name: "BlindAuction.sol",
    title: "Unchecked Send + Locked Ether",
    blurb: "Highest-bidder auction. Failed refund handling and timestamp dependence.",
    severity: "high",
    loc: 42,
    source: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BlindAuction {
    address public beneficiary;
    uint256 public auctionEnd;
    address public highestBidder;
    uint256 public highestBid;

    mapping(address => uint256) public pendingReturns;
    bool ended;

    constructor(uint256 biddingTime, address payable _beneficiary) {
        beneficiary = _beneficiary;
        auctionEnd = block.timestamp + biddingTime;
    }

    function bid() external payable {
        // VULN: block.timestamp dependence
        require(block.timestamp <= auctionEnd, "auction ended");
        require(msg.value > highestBid, "bid too low");

        if (highestBidder != address(0)) {
            // VULN: unchecked send — refund silently fails
            payable(highestBidder).send(highestBid);
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function auctionEnded() external {
        require(block.timestamp >= auctionEnd, "not ended yet");
        require(!ended, "already ended");
        ended = true;

        // VULN: transfer can revert, locking auction state
        payable(beneficiary).transfer(highestBid);
    }
}`,
    findings: [
      {
        id: "unchecked-send",
        check: "unchecked-send",
        impact: "Medium",
        confidence: "High",
        title: "Return value of `send` ignored in bid()",
        location: "bid()",
        lines: [22, 23, 24],
        description:
          "`payable(highestBidder).send(highestBid)` does not check the return value. If the refund fails, the previous bid is silently lost while their bid is overwritten.",
      },
      {
        id: "timestamp",
        check: "timestamp",
        impact: "Low",
        confidence: "Medium",
        title: "Dangerous timestamp comparison",
        location: "bid(), auctionEnded()",
        lines: [19, 30],
        description:
          "Uses `block.timestamp` for comparison. Miners can manipulate block timestamps by up to ~15 seconds, which may be exploitable depending on bidding window precision.",
      },
      {
        id: "locked-ether",
        check: "locked-ether",
        impact: "Medium",
        confidence: "Medium",
        title: "Auction can be locked by failing transfer",
        location: "auctionEnded()",
        lines: [33, 34, 35, 36, 37],
        description:
          "`payable(beneficiary).transfer(highestBid)` reverts on failure. If the beneficiary is a contract whose fallback consumes >2300 gas, the auction is permanently stuck.",
      },
    ],
  },
];

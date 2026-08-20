// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title VulnerableVault
 * @notice A simple vault contract with emergency pause functionality.
 *         This is the TARGET contract that Aegis Protocol protects.
 *         In production, any DeFi protocol's pausable contract would be the target.
 */
contract VulnerableVault is Pausable, Ownable {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    uint256 public pauseCount;
    uint256 public lastPauseTime;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event EmergencyPauseTriggered(address indexed caller, uint256 timestamp, uint256 blockNum);
    event VaultUnpaused(address indexed caller, uint256 timestamp);

    constructor() Ownable(msg.sender) {}

    /// @notice Deposit ETH into the vault
    function deposit() external payable {
        require(!paused(), "Vault is paused");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Withdraw ETH from the vault
    /// @param amount Amount of ETH to withdraw
    function withdraw(uint256 amount) external {
        require(!paused(), "Vault is paused");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Emergency pause — called by Aegis Protocol executor bot
    function triggerEmergencyPause() external onlyOwner {
        _pause();
        pauseCount++;
        lastPauseTime = block.timestamp;
        emit EmergencyPauseTriggered(msg.sender, block.timestamp, block.number);
    }

    /// @notice Unpause the vault after investigation
    function unpause() external onlyOwner {
        _unpause();
        emit VaultUnpaused(msg.sender, block.timestamp);
    }

    /// @notice Get vault status
    function getStatus() external view returns (
        bool isPaused,
        uint256 totalBalance,
        uint256 deposits,
        uint256 pauses,
        uint256 lastPause
    ) {
        return (
            paused(),
            address(this).balance,
            totalDeposits,
            pauseCount,
            lastPauseTime
        );
    }

    receive() external payable {
        deposit();
    }
}
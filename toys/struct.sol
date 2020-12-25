// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.7.5;

contract Struct {

    struct Checkpoint {
        uint128 rewardPerToken;
        uint128 reward;
    }

    mapping(address => Checkpoint) public checkpoints;

    uint128 public rewardPerToken;

    function updateRewardCheckpoint(address account) external {
        checkpoints[account] = Checkpoint(rewardPerToken, rewardOf(account));
        /*
        Checkpoint memory cp = Checkpoint(rewardPerToken, rewardOf(account));
        checkpoints[account] = cp;
        */
    }

    function rewardOf(address account) public view returns (uint128) {
        Checkpoint memory cp = checkpoints[account];
        return cp.reward + cp.rewardPerToken;
    }

}

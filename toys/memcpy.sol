// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.6.11;

contract memcpy {
//  bytes data;

//  function foo(bytes memory d) public {
//      data = d;
//  }

    uint[] data;

    function foo(uint[] calldata d) external {
        data = d;
    }
}

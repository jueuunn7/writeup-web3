// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts

pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ERC20} from "./ERC20.sol";
import {ERC2771Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";

contract Level {
    ERC1337 public token;
    uint256 public solved;
    
    constructor() {
        token = new ERC1337("DHT");
    }

    // balance가 1이면 solved
    function solve() external {
        if (token.balanceOf(address(this)) == 1) {
            solved = 1;
        }
    }
}

contract ERC1337 is ERC20, EIP712, Nonces, ERC2771Context {
    bytes32 private constant PERMIT1_TYPEHASH = keccak256("Permit(string note,address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private constant PERMIT2_TYPEHASH = keccak256("Permit(address origin,address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    error ERC2612ExpiredSignature();
    error ERC2612InvalidSigner();

    // 초기 9999 ether 발행
    constructor(string memory name) ERC20(name, "") EIP712(name, "1") ERC2771Context(address(0)) {
        _mint(_msgSender(), 9999 ether);
    }

    function permitAndTransfer(
        string memory note,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        if (block.timestamp > deadline) {
            revert ERC2612ExpiredSignature();
        }

        if (!_verifySignatureType1(
            owner, 
            _hashTypedDataV4(keccak256(abi.encode(
                PERMIT1_TYPEHASH,
                note,
                owner,
                spender,
                value,
                _useNonce(owner),
                deadline
            ))), 
            v, r, s
        ) && !_verifySignatureType2(
            owner, 
            _hashTypedDataV4(keccak256(abi.encode(
                PERMIT2_TYPEHASH,
                tx.origin,
                owner,
                spender,
                value,
                _useNonce(owner),
                deadline
            ))), 
            v, r, s
        )) {
            revert ERC2612InvalidSigner();
        }

        _approve(owner, spender, value);
        _transfer(owner, spender, value);
    }

    function ecrecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public pure returns (address) {
        return ECDSA.recover(hash, v, r, s);
    }

    function _verifySignatureType1(
        address owner,
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view returns (bool) {
        try this.ecrecover(hash, v, r, s) returns (address signer) {
            return signer == owner;
        } catch {
            return false;
        }
    }

    function _verifySignatureType2(
        address owner,
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view returns (bool) {
        try this.ecrecover(hash, v, r, s) returns (address signer) {
            return signer == _msgSender() || signer == owner;
        } catch {
            return false;
        }
    }

    function nonces(address owner) public view override(Nonces) returns (uint256) {
        return super.nonces(owner);
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function isTrustedForwarder(address forwarder) public view override(ERC2771Context) returns (bool) {
        uint256 calldataLength = msg.data.length;
        uint256 contextSuffixLength = _contextSuffixLength() + 32;
        if (calldataLength >= contextSuffixLength && 
            bytes32(msg.data[calldataLength - contextSuffixLength:calldataLength - contextSuffixLength + 32]) == keccak256(abi.encode(name()))) {
            return true;
        } else {
            return super.isTrustedForwarder(forwarder);
        }
    }
}

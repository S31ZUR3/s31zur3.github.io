Beginner
## Initial Observations

Relevant code portion:
```

bet = float(input("Enter your bet amount: ").strip())
if bet > coins:     
	print("Invalid bet.")     
	continue  ...  
if guess == winning:     
	coins += bet * 2 
else:     
	coins -= bet
```

There is **no validation** that the bet must be positive.

---

## Vulnerability Analysis

The game checks:

`if bet > coins:`

but **does not check for negative values**, allowing bets such as:

`-99999999999`

If the guess is wrong (which is extremely likely because the range is 0–1,000,000):

`coins -= bet`

If bet is negative:

`coins = coins - (-99999999999)`
`coins = coins + 99999999999`

This results in the balance skyrocketing instead of decreasing.

---

## Exploitation

### Step 1 — Start Game

`python3 21blackjack.py`

### Step 2 — Choose Play

`1`

### Step 3 — Use Negative Bet

`Enter your bet: -99999999999`
`Enter your guess: 1`

### Step 4 — Intentionally Lose

You almost certainly lose, causing coins to increase drastically.

### Step 5 — Buy Flag

`2`

---

## 🎯 Flag

`UNLP{IlovethisTown.ILoveThisGameAnd,Jim,IMightEvenLoveYou}`
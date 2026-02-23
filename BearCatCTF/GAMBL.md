#Pwn 
## Vulnerability Analysis
The vulnerability lies in the `gamble()` function within `speculative_piracy.c`:

```c
void gamble() {
    // ...
    printf("
How much would you like to bet?
 > ");
    scanf("%f", &moneyBet); // [1] moneyBet is updated here

    if ( moneyBet > money ) {
        // [2] Error is printed, but moneyBet is NOT reset
        printf("
You don't have enough money to bet that much! And you can't go into debt either.
");
    } else if ( moneyBet < 0.0 ) {
        // ...
    } else {
        money -= moneyBet;
    }
}
```

At `[1]`, the global variable `moneyBet` is updated with the user's input. At `[2]`, if the user bets more than they have, an error message is printed, but `moneyBet` retains the high value.

In the `main` loop, the program checks if the current day is a "winning" day based on the `values` array:
`int values[5] = {5, 2, 10, 8, 13};`

```c
if ( betOn && isWinning(day) ) {
    money += moneyBet * 2;
}
```

If `isWinning(day)` returns true (e.g., on Day 2, 5, 8, 10, or 13), the massive `moneyBet` is doubled and added to the user's balance, even though it was never successfully deducted.

## Exploitation
1. **Wait for Day 2**: Skip Day 1 by choosing "Complete day".
2. **Place a Huge Bet**: On Day 2, choose "Place a bet" (Option 1).
3. **Input a Large Amount**: Enter a value like `10,000,000`. The program will claim you don't have enough money, but the value is stored in `moneyBet`.
4. **Complete the Day**: Select "Complete day" (Option 3). Since Day 2 is a winning day, the program calculates `money += 10,000,000 * 2`, resulting in over $20,000,000.
5. **Buy the Flag**: Choose "Buy Flag" (Option 4).

## Flag
`BCCTF{1_Ju57_G0t_Macro_Pwnoed_D:}`

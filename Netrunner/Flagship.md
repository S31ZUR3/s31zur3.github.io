#Pwn 

## Vulnerability: Integer Overflow
The application calculates the total cost of knockoff flags using 32-bit signed integers. 
The formula is: `total_cost = quantity * 900`.

In a 32-bit signed integer system, the maximum positive value is **2,147,483,647**. If a calculation exceeds this value, it "wraps around" to the negative range (starting from -2,147,483,648).

By providing a specifically calculated quantity, we can force the `total_cost` to become negative. When the program subtracts this negative cost from our balance (`balance = balance - total_cost`), it effectively adds the amount to our balance.

## Exploitation Strategy
We need our balance to reach at least $100,000 without exceeding the 32-bit signed integer limit (which would make our balance negative and prevent the purchase).

### Calculations
1. **Targeting a negative cost:** We want `quantity * 900` to result in a negative number when cast to a 32-bit signed integer.
2. **Finding the right quantity:**
   * If we use `quantity = 4,771,075`:
   * `4,771,075 * 900 = 4,293,967,500`.
   * As a 32-bit signed integer, this wraps to: `4,293,967,500 - 4,294,967,296 = -999,796`.
3. **Updating Balance:**
   * `New Balance = 1,100 - (-999,796) = 1,000,896`.
   * This balance is well above the $100,000 required and below the overflow limit for the balance variable.

## Step-by-Step Solution
1. **Connect to the service:**
   ```bash
   nc netrunner.kurukshetraceg.org.in 5023
   ```
2. **Navigate to the Flag Shop:**
   * Enter `2` (Buy Flags)
   * Enter `1` (Definitely not the flag Flag)
3. **Trigger the Overflow:**
   * When asked for quantity, enter: `4771075`
4. **Purchase the 1337 Flag:**
   * Enter `2` (Buy Flags)
   * Enter `2` (1337 Flag)
   * Enter `1` to confirm the purchase.

The flag will then be revealed in the output.

## Flag
`CTF{Flagsh!p_sale_is_onnn}`

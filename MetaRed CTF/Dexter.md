web

The challenge "dexter" involved a Flask application using JWT for authentication. The vulnerability lay in the weak generation of the `secret_key`. The key was generated using `random.randint` seeded with a value that itself came from `random.randint(0, 2000)`. This effectively reduced the possible key space to only 2001 possibilities, making it trivial to brute-force.

I solved the challenge by:
1.  **Analyzing the Source Code:** I identified the weak seed generation logic in `app.py`.
2.  **Fetching a Valid Token:** I made a request to the server to obtain a valid JWT signed with the active secret key.
3.  **Brute-Forcing the Key:** I wrote a Python script to iterate through all 2001 possible seeds, generating the corresponding keys and attempting to verify the server's token.
4.  **Forging a Token:** Once the correct key (`Rem1xKey86426418499`) was found, I forged a new JWT with the payload `{"role": "superuser", "user": "admin"}`.
5.  **Retrieving the Flag:** I used the forged token to authenticate with the server and retrieve the flag.

**Flag:** `UNLP{R34llY-ur-Us1ng-Ai_for_th1s-B4by-Ch4ll3ng3?}
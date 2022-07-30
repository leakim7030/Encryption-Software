# Password Manager / Encryption

Created as hobby project during first year studies of B.sC in Applied Data Science in the programming and databases course, using python and sqlite.

A pin and security questions are set during the first run of the program, after intial setup, a user is required to enter the pin + one random security question in order to be able to do anything further.

Currently enables the user to store and retrieve a username/password for a specific domain, e.G Facebook.com in sqlite database.

It has fuinctionality that can encrypt messages that is not enabled in the main function, it works by creating a key (randomized array) which is stored in a table called "Keys", a user then writes a string that gets encrypted by for example a -> ! and b -> F and c -> e etc and chooses a keyID (for example 35).
The messageId, message and keyID is stored in the database, this could enable a user to find specific messages by its messageID. 

To decrypt this message you are currently required to enter the encrypted string along with the keyId (The speciffic key containing the randomized array).

There are a lot of improvements or further development that could be done to improve user experience

ERRORS:
DB schema should be updated to remove keyID from passwords table


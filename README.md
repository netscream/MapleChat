MapleChat
===

##About
A secure chat server written in C using OpenSSL. The server is heavily based on IRC.

##Usage
###Server
To run the server execute

```
./chatd [PORT]
```
where `[PORT]` is a port number that is not in use on this system.

###Client
To run the client execute

```
./chat [ADDRESS] [PORT]
```
where `[PORT]` is a port number that is not in use on this system and `[ADDRESS]`
is an address of a host running the server.

###Development
```
$ make                (Will compile the server)
$ make & make install (Will compile the server and install) (*needs evelated priveledges* **root access in most cases**)
$ make distclean      (Will clean all compiled .o and application files)
$ make run_server      (Will run a new instance of the chat server)
$ make run_client      (Will run a new instance of the chat client)
```

##Modules

###chatd.c
Calls `run_server` in server.c

###chat.c
Calls `run_client` in client.c

###server.c (server.h)
Main loop of the server. Here we initialize all of the data structures we need for the
server to function. In each iteration of the main loop, we check if incoming connections
are coming in on the main socket, if so we initialize a new connection adding a new user
to our user list. Then we iterate through each connection in our connection list and check
if their file descriptor is active, if so we process their message. We send a `ping` to the
client every two iterations (every minute), if the client doesn't respond with a `pong`
within 30 seconds we assume it's idle and disconnect the user.

###client.c (client.h)
This is our code for the client. It has all of the commands requested in the handout. When
it recieves a `ping` from the server it sends a `pong` bac.

###printing.c (printing.h)
Responsible for all printing to the console.

###debugging.c (debugging.h)
Only for debugging the applictaion. To be able to use these functions
please change the "#define debug" macro inside debugging.h to 1 etc. (#define debug 1)

###user.c (user.h)
Includes logic for user authentication and disconnecting of users.

When authenticating a user, we check if we already stored a hash for that user, if not
we create a new user and generate a salted hash of the user's password storing both the
hash and the salt in a keyfile. Otherwise we hash the incoming password and check if it
matches the stored hash. Matching hashes means that the user has been authenticated.

When disconnecting a user we remove the user from the connection list and delete the user
object.

###processing.c (processing.h)
Here we process all the messages from the client.

In `process_message` we check if the message is a request for any of the available
commands. When a command is matched, a function for that command is called.

If we recieve a `PONG` message from the client, we reset the `login_timeout` of the
user so he doesn't get disconnected.

If no command is matched, the message is assumed to be a message to the current
chat room.

###structures.h
Contains all the structs required for the application. We have structs for user information,
room information, communication messages, games and more.

###iterators.c (iterators.h)
Here we store our iterators which are used to iterate through all users, connections or chat rooms.

###game.c (game.h)
Our game is defined in here. You can play it by running `/game <username>`, the challenged user will
then need to either `/accept` or `/decline` the game. When a game has started you can `/roll` and see
which user won.

###authentication.c (authentication.h)
Functionality which relates to hashing passwords, storing and retrieving said hashes and generating
salts. (explained in `user.c`)

##File structure

```
.
├── AUTHORS        *List of authors*
├── cert
│   ├── fd.crt
│   ├── fd.csr
│   ├── fd.key
│   └── fd-public.key
├── cleanup.py
├── getpasswd.c
├── pa3.pdf        *PDF file for project, about implementation*
├── README        *THIS FILE!!*
└── src
    ├── cert
    │   ├── fd.crt
    │   ├── fd.csr
    │   ├── fd.key
    │   └── fd-public.key
    ├── chat
    ├── chat.c
    ├── chatd
    ├── chatd.c
    ├── libs
    │   ├── authentication.c
    │   ├── authentication.h
    │   ├── client.c
    │   ├── client.h
    │   ├── debugging.c
    │   ├── debugging.h
    │   ├── game.c
    │   ├── game.h
    │   ├── getpasswd.c
    │   ├── getpasswd.h
    │   ├── iterators.c
    │   ├── iterators.h
    │   ├── printing.c
    │   ├── printing.h
    │   ├── processing.c
    │   ├── processing.h
    │   ├── server.c
    │   ├── server.h
    │   ├── structures.h
    │   ├── user.c
    │   └── user.h
    ├── Makefile
    └── passwords.ini
```

##Comments
We will use RSA for key generation
###Private key
```
$ openssl rsa -text -in fd.key
Passphrase for Openssl private key = fool
```

###Certificate request values (CSR)

```
$ openssl req -new -key fd.key -out fd.csr
Country Name (2 letter code) [XX]:IS
State or Province Name (full name) []:
Locality Name (eg, city) [Default City]:Reykjavik
Organization Name (eg, company) [Default Company Ltd]:Foo inc
Organizational Unit Name (eg, section) []:.
Common Name (eg, your name or your server's hostname) []:tolvur.net
Email Address []:hlynur@tolvur.net

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:fool
An optional company name []:.
```

###Certificate
```
$ openssl x509 -req -days 365 -in fd.csr -signkey fd.key -out fd.crt
************* Certificate creation is now done *******************
Not so much security choosing the same password for the key and the
challange password.
******************************************************************
```

##Version History

##Implementation of problems
    |- 1) *DONE*
        See comment section for implementation
    |- 2) *DONE*
        See server.c and client.c
    |- 3) *DONE*
        see server.c and client.c
    |- 4) *DONE*
        see processing.c
    |- 5) *DONE*
        see processing.c
    |- 6)
        |- 6.1 *DONE*
            see authentivaction.c
        |- 6.2
            The passwords are stored in a key file which is located at `src/passwords.ini`.
            The base64 encoded password hashes are stored in the `passwords` section, while
            the salt is stored in plaintext in the `salts` section. Due to the fact that all
            communication between the server and client are encrypted through public key
            encryption, makes it impossible for someone without the private key to be able
            to read the password in transit. So it is safe to send the password in plaintext
            over this encrypted connection.

            If our server would be breached by an attacker, he would be able to access our
            private key. With the private key he can decrypt all incoming messages to the
            server, making him able to see the user passwords in plaintext. If we would
            hash the passwords client-side, then this wouldn't be an issue.
    |- 7)
        |- 7.1 *DONE*
            see processing.c
        |- 7.2
            Private message should not be logged, then they wouldn't be private any more.
            No meta data about the messages are logged, it's none of the admin's business
            which users are privately conversing.

            Due to this, our chat server is truly secure due to the fact that there aren't
            any unencrypted logs of all messages on the server, which would in turn make
            the chat server less secure. We make sure that the no one is able to retrieve
            the contents of the conversation after it happend, making it a great place
            to discuss top secret plans along with informing your friend Stacy that you
            have a crush on Chad from school.
    |- 8)
        |- 8.1 *DONE*
            see iterators.c
        |- 8.2
            One could create thousands of connections to the server
            An attacker might deploy a Denial of Service attack on the server by opening up
            a bunch of connections while not maintaining them. This would leave the chat
            server filled with zombie users, making it impossible for legitimate users to
            connect to the server during the attack.

            We employ a Ping/Pong technique to handle idle clients. The server sends a `ping`
            to the client every 60 seconds. If the client doesn't respond with a `pong` within
            30 seconds, the client is assumed to be idle and the connection is closed.
    |- 9)
        |- 9.1 *DONE*
            see game.c
        |- 9.2
            If the attacker is able to control the seed of the PRNG, he will be able to predict
            whether he will win a game or not. The seed of our PRNG is the time of when the
            server started. So if the attacker is able to forcefully restart the server (throug
            crashes or other means) he is able to determine the seed of the PRNG.

            This attack can be combated by making the entropy of the seed larger by making it
            depend on more variables than just the start time.

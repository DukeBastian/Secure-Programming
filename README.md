# Secure-Programming
Autumm Project for Cybersecurity

# Secure Password Manager

## Project Scope
A simple, secure local password manager built in Java to safely store and retrieve credentials using a master password, designed to protect against memory scavenging and local attacks.

## Planned Command-Line Commands
* Create a new encrypted password vault.
* `add <service> <username> <password>` - Store a new credential.
* `get <service>` - Retrieve a stored password.
* `list` - Display all stored service names.

## How to Build and Run
1. Ensure Java Development Kit is installed.
2. Compile the source files:
   ```bash
   javac Main.java

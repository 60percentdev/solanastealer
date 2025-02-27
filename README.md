# Solana Wallet Scanner and Balancer

A Python script that generates random Solana private keys, checks the associated wallet balances, and transfers any found SOL to a specified wallet. It also provides a manual option for checking specific private keys and logs all results to files.

## Features

- **Random Private Key Generation:** Generates and checks random Solana wallet keys.
- **Balance Checking:** Retrieves SOL balances for the generated wallets.
- **Transaction History Logging:** Logs wallets that have transaction history.
- **Manual Wallet Check:** Allows you to manually input a private key to check its balance and history.
- **Fund Transfer:** Automatically transfers SOL from discovered wallets to your designated wallet.
- **Configurable:** Easily customize settings through the `config.json` file.

## Prerequisites

- Python 3.7 or higher
- Required Libraries:
  - `base58`
  - `pynacl`
  - `solana`
  - `solana.publickey`
  - `cachetools`

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/your-username/solana-wallet-scanner.git
   cd solana-wallet-scanner

2. Install dependencies:
   ```bash
   pip install base58 pynacl solana solana.publickey cachetools

3. Update `config.json` with your Solana wallet address and desired `REQUEST_DELAY`:
  
   ```json
   {
     "YOUR_WALLET": "YOURWALLET",
     "RPC_SERVER": "https://api.mainnet-beta.solana.com"  "REQUEST_DELAY": 0.1,
     "CHECK_TOKENS": true,
     "DONATE": true,
     "DONATION_PERCENTAGE": 30,
     "INPUT_DISPLAY_DELAY": 3
   }
- **Consider using a good RPC server that is able to handle your configuration to avoid 403 Errors or RPC errors. Helius is quite a good option! Default from config is not very good** :
4. Run the script:
   ```bash
   python app.py

5. To manually check a private key, input the private key. Results are saved in `output_command.txt`.

---

## Files

- **`app.py`**: Main script.
- **`config.json`**: Configuration file.
- **`found_wallets.txt`**: Logs wallets with balances.
- **`potential.txt`**: Logs wallets with transaction history.
- **`output_command.txt`**: Logs manual check results.

---

## Notes

- **Private Key Security**: Never share private keys.
- **Rate Limiting**: Adjust `REQUEST_DELAY` in `config.json` if needed.
- **Legality**: Unauthorized access to wallets is illegal. Use responsibly.
- **Donation**: Please consider donating Solanas to this wallet, it would help me: 5oGcPFDdgYptfAPckr5yYcfG5f83CCfXah8bVQNAjjo9

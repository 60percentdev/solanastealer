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
  - `solders`

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/your-username/solana-wallet-scanner.git
   cd solana-wallet-scanner

2. Install dependencies:
   ```bash
   pip install base58 pynacl solana solders

   ## Usage

1. Update `config.json` with your Solana wallet address and desired `REQUEST_DELAY`:
   ```json
   {
     "YOUR_WALLET": "8Y7zQZ9pXy3T2w1vR4sD6fGhJkLmNqW2e",
     "REQUEST_DELAY": 1
   }

2. Run the script:
   ```bash
   python app.py

3. To manually check a private key, input it when prompted. Results are saved in `output_command.txt`.

4. Press `Ctrl+C` to stop the script.

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

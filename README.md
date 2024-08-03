# pyNoteMinter

Based on [pyNoteWallet](https://github.com/NoteScan/pyNoteWallet), pyNoteMinter is optimized for minting tokens on the NOTE protocol.

## Installation (Windows)

1. **Download and Install Python**

   - Download Python from [python.org](https://www.python.org/downloads/) or install it via the Microsoft Store on Windows.

2. **Get the pyNoteMinter Source Code**

   - Download the source code from [this link](https://github.com/NoteScan/pyNoteMinter/archive/refs/heads/main.zip).
   - Unzip the downloaded file to a folder on your computer.

3. **Install Required Modules**

   - In File Explorer, double-click `install.bat` to install the necessary modules.

## Quick Start

1. **Minting on BTC Network**

   - For minting on the BTC mainnet, double-click `mint_livenet.bat`.
   - For minting on the BTC testnet, double-click `mint_testnet.bat`.

2. **Wallet Information**

   - pyNoteMinter will create a new wallet for you. Use the command:
     ```
     info
     ```
     to view wallet information.

   - Deposit a small amount of BTC into the `mainAddress` for gas fees. Currently, about 2 USDT worth of BTC is needed for one mint.

   - **Important:** Back up the mnemonic as soon as possible. Use:
     ```
     info --m True
     ```
     to display the wallet information including the mnemonic. Save it in a secure location.

3. **Start Minting**

   - Once you have sufficient gas fees, use the `mint` command to start minting. For example:
     ```
     mint fight
     ```
     This command will attempt to mint the FIGHT token. If the initial attempt fails, pyNoteMinter will automatically halve the amount and retry.

   - To mint multiple times, for example, 10 times, use:
     ```
     mint fight --loop 10
     ```
     or
     ```
     mint fight --l 10
     ```

   - If you know the maximum amount per mint (e.g., 8192), you can specify it with:
     ```
     mint fight --amount 8192 --loop 10
     ```
     or
     ```
     mint fight --a 8192 --l 10
     ```

## Additional Options

- `--stop True`
  - Stops minting on failure. Default is `False`, which means the minting process will continue until successful.

- `--half False`
  - Disables the 'Auto-halving Amount' feature.

- `--bitwork xxx`
  - Replaces the default bitwork value of 20 with the specified value.

- `--feerate slow` or `--feerate fast`
  - Replaces the default feerate value of avg with the specified value.
  
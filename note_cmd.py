import argparse
import cmd
import time
import os
import io
import sys
import shlex
import qrcode
from dotenv import set_key
from pprint import pprint
from btc_wallet import BTCWallet
from config import WALLET_MNEMONIC, coins
from mint import mint_token


class CommandLineWallet(cmd.Cmd):
    prompt = '> '
    intro = "Welcome to the Command Line Wallet. Type help or ? to list commands.\n"
    mnemonic = WALLET_MNEMONIC

    def __init__(self, network=None):
        super().__init__()
        self.wallets = {}
        self.current_wallet = None
        self.init_wallets(network)

    def save_mnemonic(self):
        if self.mnemonic != WALLET_MNEMONIC:
            print('Saving to .env file...')
            env_file_path = '.env'
            if not os.path.exists(env_file_path):
                with open(env_file_path, 'w', encoding='utf-8') as env_file:
                    env_file.write('')
            set_key(env_file_path, 'WALLET_MNEMONIC', self.mnemonic)        

    def init_wallets(self, network=None):
        print("Initializing wallets...")
        for coin in coins:
            if coin.symbol == "BTC":
                if coin.network == "livenet" and (not network or network == 'livenet'):
                    self.wallets['BTClivenet'] = BTCWallet(self.mnemonic, coin)
                    if self.wallets['BTClivenet'].mnemonic != self.mnemonic:
                        self.mnemonic = self.wallets['BTClivenet'].mnemonic
                        self.save_mnemonic()
                    if len(coins) == 1 or network == 'livenet':
                        self.current_wallet = self.wallets['BTClivenet']
                        break
                elif coin.network == "testnet" and (not network or network == 'testnet'):
                    self.wallets['BTCtestnet'] = BTCWallet(self.mnemonic, coin)
                    if self.wallets['BTCtestnet'].mnemonic != self.mnemonic:
                        self.mnemonic = self.wallets['BTCtestnet'].mnemonic
                        self.save_mnemonic()
                    if len(coins) == 1 or network == 'testnet':
                        self.current_wallet = self.wallets['BTCtestnet']
                        break
        self.set_prompt()

    def set_prompt(self):
        if self.current_wallet:
            self.prompt = f"{self.current_wallet.config.network} 0> "
        else:
            self.prompt = 'Enter use testnet/use livenet to select a wallet> '

    def do_use(self, args):
        """use [network] - select a wallet"""
        parser = argparse.ArgumentParser(prog='use', description='Select a wallet')
        parser.add_argument('network', type=str, help='BTC testnet or BTC livenet')
        try:
            parsed_args = parser.parse_args(shlex.split(args))
            network = 'BTC' + parsed_args.network
            self.current_wallet = self.wallets[network]
            if self.current_wallet:
                print(f'Using {network} wallet')
                self.set_prompt()
            else:
                print(f'Wallet for {network} not found')
        except Exception as e:
            print(e)                    
        except SystemExit:
            pass

    def do_balance(self, args):
        """balance - get wallet BTC balance"""
        if not self.current_wallet:
            print("No wallet selected")
            return
        result = self.current_wallet.get_balance()
        pprint(result)

    def do_info(self, args):
        """info - get wallet info"""
        parser = argparse.ArgumentParser(prog='info', description='Show wallet info')
        parser.add_argument('--mnemonic', type=bool, default=False, help='Show Mnemonic, default=False')

        try:
            parsed_args = parser.parse_args(shlex.split(args))
            if not self.current_wallet:
                print("No wallet selected")
                return

            result = self.current_wallet.info()
            print('network:', result['network'])
            print('rootPath:', result['rootPath'])
            if parsed_args.mnemonic:
                print('Mnemonic:', result['mnemonic'])
            print('mainAddress:', result['currentAccount'].main_address.address)
            print('( Please deposit some BTC to this address for using as gas fee. )')
            qr = qrcode.QRCode()
            qr.add_data(result['currentAccount'].main_address.address)
            f = io.StringIO()
            qr.print_ascii(out=f)
            f.seek(0)
            print(f.read())
            print('tokenAddress:', result['currentAccount'].token_address.address)
        except SystemExit:
            pass
        except Exception as e:
            print(e)

    def do_mint(self, args):
        """mint [tick] [--amount amount_per_mint] [--loop loop_mint] [--bitwork bitwork] [--stop stop_on_fail] [--half auto halving] - mint token"""
        parser = argparse.ArgumentParser(prog='mint', description='Mint token')

        parser.add_argument('tick', type=str, help='Token tick')
        parser.add_argument('--amount', type=float, default=0, help='Amount in one unit of token, float value')
        parser.add_argument('--loop', type=int, default=1, help='Number of successful minting, default=1')
        parser.add_argument('--bitwork', type=str, default='20', help='Bitwork, default=20')
        parser.add_argument('--stop', type=bool, default=False, help='Stop loop on fail, default=False')
        parser.add_argument('--half', type=bool, default=True, help='Auto halving, default=True')

        try:
            parsed_args = parser.parse_args(shlex.split(args))
            if not self.current_wallet:
                print("No wallet selected")
                return
            token_info = self.current_wallet.token_info(parsed_args.tick)
            if not token_info:
                print("Token not found")
                return

            dec = int(token_info['dec'])
            lim = int(token_info['lim'])
            max = int(token_info['max'])
                    
            if parsed_args.amount == 0:
                amount = lim
            else:
                amount = int(parsed_args.amount * 10 ** dec)
                if amount > lim:
                    print("Amount exceeds limit, set to limit")
                    amount = lim

            n = 0
            while n < parsed_args.loop:
                print(f"Minting {parsed_args.tick} {n+1}/{parsed_args.loop}...")
                try:
                    result = mint_token(self.current_wallet,
                                        parsed_args.tick,
                                        amount,
                                        parsed_args.bitwork)
                    print(result)
                    if result['success']:
                        n += 1
                    elif parsed_args.stop:
                        break
                    elif parsed_args.half and 'code' in result['error'] and result['error']['code'] == 400:
                        if max - int(result['error']['message']['total']) < amount:
                            amount = max - int(result['error']['message']['total'])
                        else:
                            amount /= 2
                        print(f"Auto halving amount to {amount / (10 ** dec)}")
                    else:
                        time.sleep(15)
                except Exception as e:
                    print(e)
                    time.sleep(15)
        except SystemExit:
            pass

    def do_exit(self, args):
        """exit the wallet"""
        print("Exiting wallet")
        self.save_mnemonic()

        return True

    def default(self, line):
        print(f"Unknown command: {line}")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        network = sys.argv[1]
        CommandLineWallet(network).cmdloop()
    else:
        CommandLineWallet().cmdloop()

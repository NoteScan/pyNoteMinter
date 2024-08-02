from typing import List
import time
import requests
import msgpack
import bip32utils
from mnemonic import Mnemonic

from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup

from n_types import *
from constants import *
from utils import split_buffer_into_segments, sort_dict_by_key
from btc_notes import generate_p2wpkh_address, generate_p2tr_note_address
from btc_psbt import create_coin_psbt, create_p2tr_note_psbt
from config import MIN_SATOSHIS, CoinConfig
from urchain import Urchain

class BTCWallet():
    def __init__(self, mnemonic: str, config: CoinConfig, lang: str = "english"):
        self.config = config
        self.lang = lang
        self.urchain = Urchain(config.urchain['host'], config.urchain['apiKey'])
        self._account_index = 0
        self.current_account = None
        self.account_collection = {}
        self.wallet = None
        self.root_hd_private_key = None
        self.child_hd_key = None

        self.import_mnemonic(mnemonic, lang)

        self.urchain.health()

    @property
    def xpub(self):
        return self.root_hd_private_key.ExtendedKey(private=False, encoded=True)

    def import_mnemonic(self, mnemonic_str: str, lang: str = "english"):
        mnemonic = Mnemonic(lang)
        if mnemonic_str == '':
            print('No mnemonic provided, generating new one...')
            mnemonic_str = mnemonic.generate()

        self.mnemonic = mnemonic_str
        seed = mnemonic.to_seed(mnemonic_str)
        # Create a BIP32 root key (master key) from the seed
        self.root_hd_private_key = bip32utils.BIP32Key.fromEntropy(
            seed,
            testnet= self.config.network == "testnet")
        root_path1 = 0
        if self.config.network == "testnet":
            root_path1 = 1
        self.current_account = self.create_account(44, root_path1, 0, 0, 0)

    def create_account(self,
                       root: int,
                       root_path1: int,
                       root_path2: int,
                       index: int,
                       target: int) -> IWalletAccount:
        ext_path = f'm/{index}/{target}'
        root_hd_key = self.root_hd_private_key.ChildKey(root + bip32utils.BIP32_HARDEN).ChildKey(
            root_path1 + bip32utils.BIP32_HARDEN).ChildKey(root_path2 + bip32utils.BIP32_HARDEN)

        self.child_hd_key = root_hd_key.ChildKey(index).ChildKey(target)

        account = IWalletAccount(target=target,
                                 index=index,
                                 ext_path=ext_path,
                                 xpub=root_hd_key.ExtendedKey(private=False, encoded=True),
                                 private_key=self.child_hd_key.WalletImportFormat(),
                                 public_key=self.child_hd_key.PublicKey().hex())
        self.account_collection[ext_path] = account
        network = 'testnet' if self.config.network == 'testnet' else 'mainnet'
        account.main_address = generate_p2wpkh_address(account.public_key, network)
        account.token_address = generate_p2tr_note_address(account.public_key, network)        
        return account

    def get_token_utxos(self, tick: str, amount: Optional[int]):
        token_utxos = self.urchain.tokenutxos([self.current_account.token_address.script_hash],
                                              tick,
                                              amount)
        if len(token_utxos) == 0:
            raise Exception("No UTXOs found")
        return token_utxos

    def fetch_all_account_utxos(self, include_unbonded_token_utxos: bool = False) -> List[IUtxo]:
        all_script_hashs = []
        all_accounts = {}
        for account in self.account_collection.values():
            all_script_hashs.append(account.main_address.script_hash)
            all_accounts[account.main_address.script_hash] = account
            if include_unbonded_token_utxos:
                all_script_hashs.append(account.token_address.script_hash)
                all_accounts[account.token_address.script_hash] = account
        all_utxos = self.urchain.utxos(all_script_hashs)
        for utxo in all_utxos:
            account = all_accounts.get(utxo.script_hash)
            if account:
                utxo.private_key_wif = account.private_key
                if utxo.script_hash == account.main_address.script_hash:
                    utxo.type = account.main_address.type
                if utxo.script_hash == account.token_address.script_hash:
                    utxo.type = account.token_address.type
        return all_utxos

    def broadcast_transaction(self, tx: ITransaction) -> IBroadcastResult:
        return self.urchain.broadcast(tx.tx_hex.hex())

    def best_block(self):
        results = self.urchain.best_block()
        return results

    def token_info(self, tick: str):
        result = self.urchain.token_info(tick)
        return result

    def all_tokens(self):
        results = self.urchain.all_tokens()
        return results

    def info(self):
        return {
            "coin": "BTC",
            "mnemonic": self.mnemonic,
            "lang": self.lang,
            "network": self.config.network,
            "rootXpub": self.xpub,
            "urchain": self.config.urchain,
            "faucets": self.config.faucets if self.config.faucets else None,
            "rootPath": f"m/{self.config.path_r}'/{self.config.path_r_s1}'/{self.config.path_r_s2}'",
            "currentAccount": self.current_account,
        }

    def get_balance(self):
        main_address_balance = self.urchain.balance(self.current_account.main_address.script_hash)
        token_address_balance = self.urchain.balance(self.current_account.token_address.script_hash)

        return {
            "mainAddress": {
                "confirmed": main_address_balance['confirmed'],
                "unconfirmed": main_address_balance['unconfirmed']
            },
            "tokenAddress": {
                "confirmed": token_address_balance['confirmed'],
                "unconfirmed": token_address_balance['unconfirmed']
            }
        }

    def send(self, to_addresses: ISendToAddress):
        utxos = self.fetch_all_account_utxos()
        fee_rate = self.get_fee_per_kb()
        network = 'testnet' if self.config.network == 'testnet' else 'mainnet'

        setup(network)
        private_key = PrivateKey(self.current_account.private_key)
        estimated_psbt = create_coin_psbt(
            private_key,
            utxos,
            to_addresses,
            self.current_account.main_address.address,
            network,
            fee_rate['avgFee'],
            1000
        )

        estimated_size = estimated_psbt.vsize
        real_fee = int((estimated_size * fee_rate['avgFee']) / 1000 + 1)

        final_tx = create_coin_psbt(
            private_key,
            utxos,
            to_addresses,
            self.current_account.main_address.address,
            network,
            fee_rate['avgFee'],
            real_fee
        )

        return self.urchain.broadcast(final_tx.serialize(include_witness=True).hex())

    def build_n20_transaction(self,
                              payload:NotePayload,
                              to_addresses:ISendToAddress,
                              note_utxos:List[IUtxo],
                              pay_utxos:List[IUtxo]=None,
                              fee_rate=None):
        if pay_utxos is None:
            pay_utxos = self.fetch_all_account_utxos()
        if fee_rate is None:
            fee_rate = self.get_fee_per_kb()['avgFee']

        network = 'testnet' if self.config.network == 'testnet' else 'mainnet'
        setup(network)
        private_key = PrivateKey(self.current_account.private_key)

        estimated_size = 248

        real_fee = int((estimated_size * fee_rate) / 1000 + 1)

        final_tx = create_p2tr_note_psbt(
            private_key,
            payload,
            note_utxos,
            pay_utxos,
            to_addresses,
            self.current_account.main_address.address,
            network,
            fee_rate,
            real_fee
        )
        return ITransaction(
            tx_id=final_tx.id,
            tx_hex=final_tx.serialize(include_witness=True),
            note_utxos=note_utxos,
            pay_utxos=pay_utxos,
            fee_rate=fee_rate
        )

    def build_n20_payload(self, data, use_script_size=False):
        sorted_data = sort_dict_by_key(data)
        encoded_data = msgpack.packb(sorted_data)
        payload = NotePayload("", "", "", "", "")
        buffer = bytearray(encoded_data)

        if len(buffer) <= MAX_STACK_FULL_SIZE:
            data_list = split_buffer_into_segments(buffer, MAX_STANDARD_STACK_ITEM_SIZE)
        elif use_script_size and len(buffer) <= MAX_SCRIPT_FULL_SIZE:
            data_list = split_buffer_into_segments(buffer, MAX_SCRIPT_ELEMENT_SIZE)
        else:
            raise ValueError("Data is too long")

        i = 0
        for item in data_list:
            setattr(payload, f"data{i}", item.hex())
            i += 1
        return payload

    def build_n20_payload_transaction(self,
                                      payload:NotePayload,
                                      to_address:ISendToAddress=None,
                                      note_utxo:IUtxo=None,
                                      pay_utxos:List[IUtxo]=None,
                                      fee_rate=None):
        if note_utxo is None:
            commit_address = self.current_account.token_address
            note_utxos = self.urchain.utxos([commit_address.script_hash])
            if len(note_utxos) == 0:
                result = self.send([ISendToAddress(address=commit_address.address,
                                                   amount=MIN_SATOSHIS)])
                if result['success']:
                    for _ in range(10):
                        note_utxos = self.urchain.utxos([commit_address.script_hash])
                        if len(note_utxos) > 0:
                            break
                        time.sleep(1)
                    else:
                        raise Exception("Cannot get commit note UTXO")
                else:
                    raise Exception(result['error'])
            note_utxo = note_utxos[0]
            note_utxo.type = AddressType.P2TR_NOTE

        if pay_utxos is None:
            pay_utxos = self.fetch_all_account_utxos()
            pay_utxos = [utxo for utxo in pay_utxos if utxo.script_hash != note_utxo.script_hash]

        result = self.build_n20_transaction(
            payload,
            [ISendToAddress(address=to_address, amount=MIN_SATOSHIS)],
            [note_utxo],
            pay_utxos,
            fee_rate
        )
        result.note_utxo = result.note_utxos[0] if result.note_utxos else None
        return result

    def token_list(self):
        results = self.urchain.token_list(self.current_account.token_address.script_hash)
        return results


    def get_fee_per_kb(self):
        url = "https://mempool.space"
        if self.config.network == 'testnet':
            url += "/testnet4"
        url += "/api/v1/fees/recommended"
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            raise Exception(f"Cannot get fee rate, status code: {response.status_code} url: {url}")        
        fees = response.json()
        return {
            "slowFee": min(fees['hourFee'], fees['halfHourFee']) * 1000,
            "avgFee": max(fees['hourFee'], fees['halfHourFee']) * 1000,
            "fastFee": max(fees['hourFee'], fees['halfHourFee'], fees['fastestFee']) * 1000
        }

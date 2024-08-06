import hashlib
from bitcointx import select_chain_params, set_custom_secp256k1_path
from bitcointx.wallet import P2TRBitcoinTestnetAddress, TaprootScriptTree, P2TRBitcoinAddress
from bitcointx.core.key import XOnlyPubKey
from bitcointx.core import x
from bitcointx.core.script import OP_CHECKSIG, OP_2DROP, CScript
from bitcoinutils.keys import PublicKey, P2wpkhAddress
from bitcoinutils.setup import setup

from constants import NOTE_PROTOCOL_ENVELOPE_ID
from n_types import IAddressObject, AddressType

from utils import to_x_only, get_dll_suffix

def build_note_script(x_only_pubkey):
    """
    Builds a NOTE script using the given x_only_pubkey.

    Parameters:
    - x_only_pubkey: The x-only public key to be included in the NOTE script.

    Returns:
    - script: The constructed NOTE script.

    """
    note_hex = NOTE_PROTOCOL_ENVELOPE_ID.encode().hex()
    script = CScript([x(note_hex),
                      OP_2DROP,
                      OP_2DROP,
                      OP_2DROP,
                      x(x_only_pubkey),
                      OP_CHECKSIG],
                    name='note_script')
    return script


def generate_p2wpkh_address(pubkey, network):
    """
    Generate a Pay-to-Witness-Public-Key-Hash (P2WPKH) address.

    Args:
      pubkey (str): The public key used to generate the address.
      network (str): The network to generate the address for.

    Returns:
      IAddressObject: An object containing the generated address, 
                      script, script hash, and address type.
    """
    setup(network)
    pubkey_obj = PublicKey(pubkey)
    address_obj = P2wpkhAddress(pubkey_obj.get_segwit_address().to_string())
    script = address_obj.to_script_pub_key().to_hex()
    script_hash = hashlib.sha256(bytes.fromhex(script)).digest()[::-1].hex()
    return IAddressObject(address=address_obj.to_string(),
                          script=script,
                          script_hash=script_hash,
                          type=AddressType.P2WPKH)

def generate_p2tr_note_info(pubkey:str, network='mainnet'):
    if network == 'testnet':
        select_chain_params('bitcoin/testnet')
    else:
        select_chain_params('bitcoin')

    x_only_pubkey = to_x_only(bytes.fromhex(pubkey))

    note_script = build_note_script(x_only_pubkey.hex())
    p2pk_script = CScript([x(x_only_pubkey.hex()), OP_CHECKSIG], name='p2pk_script')

    set_custom_secp256k1_path('./secp256k1' + get_dll_suffix())

    obj_pubkey = XOnlyPubKey(x_only_pubkey)
    root_tree = TaprootScriptTree([note_script, p2pk_script],
                                   leaf_version=192,
                                   internal_pubkey=obj_pubkey)

    if network == 'testnet':
        p2tr = P2TRBitcoinTestnetAddress.from_script_tree(stree=root_tree)
    else:
        p2tr = P2TRBitcoinAddress.from_script_tree(stree=root_tree)

    script_p2tr = {}
    note_p2tr = {}
    p2pk_p2tr = {}

    note_redeem = {
        'output': bytes.fromhex((root_tree.get_script('note_script').hex())),
        'redeemVersion': 192
    }

    p2pk_redeem = {
        'output': bytes.fromhex(root_tree.get_script('p2pk_script').hex()),
        'redeemVersion': 192
    }

    script_p2tr['address'] = p2pk_p2tr['address'] = note_p2tr['address'] = str(p2tr)
    script_p2tr['output'] = note_p2tr['output']= p2pk_p2tr['output'] = bytes.fromhex(p2tr.to_scriptPubKey().hex())
    script_p2tr['redeemVersion'] = note_p2tr['redeemVersion'] = p2pk_p2tr['redeemVersion'] = 192
    script_p2tr['scriptTree'] = note_p2tr['scriptTree'] = p2pk_p2tr['scriptTree'] = [{'output': note_redeem['output']}, {'output': p2pk_redeem['output']}]
    script_p2tr['signature'] = note_p2tr['signature'] = p2pk_p2tr['signature']  = None
    script_p2tr['redeem'] = None
    script_p2tr['witness'] = None

    note_p2tr['redeem'] = note_redeem
    note_p2tr['witness'] = bytes.fromhex(root_tree.get_script_with_control_block('note_script')[-1].hex())

    p2pk_p2tr['redeem'] = p2pk_redeem
    p2pk_p2tr['witness'] = bytes.fromhex(root_tree.get_script_with_control_block('p2pk_script')[-1].hex())

    return {
        'scriptP2TR': script_p2tr,
        'noteP2TR': note_p2tr,
        'p2pkP2TR': p2pk_p2tr,
        'noteRedeem': note_redeem,
        'p2pkRedeem': p2pk_redeem
    }

def generate_p2tr_note_address(pubkey, network):
    """
    Generates a Pay-to-Taproot (P2TR) NOTE address.

    Args:
      pubkey (str): The public key used to generate the address.
      network (str): The network to generate the address for.

    Returns:
      IAddressObject: An object containing the generated address, 
                      script, script hash, and address type.
    """
    setup(network)
    p2tr_note_info = generate_p2tr_note_info(pubkey, network)
    script = p2tr_note_info['scriptP2TR']['output'].hex()
    script_hash = hashlib.sha256(bytes.fromhex(script)).digest()[::-1].hex()
    return IAddressObject(address=p2tr_note_info['scriptP2TR']['address'],
                          script=script,
                          script_hash=script_hash,
                          type=AddressType.P2TR_NOTE)

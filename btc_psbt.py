from typing import List
import struct

from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.constants import SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY

from btclib.psbt.psbt import Psbt, PsbtIn, PsbtOut, extract_tx
from btclib.tx.tx import TxOut, Tx, TxIn
from btclib.tx.out_point import OutPoint
from btclib.script import ScriptPubKey, witness
from btclib.script.sig_hash import from_tx
from btclib.hashes import sha256, tagged_hash

from bitcointx.core.key import CKey
from btc_notes import generate_p2tr_note_info
from n_types import IUtxo, ISendToAddress, AddressType, NotePayload
from config import MIN_SATOSHIS

from utils import to_x_only
from constants import MAX_SEQUENCE

# Constants
EMPTY_BUFFER = b''
DEFAULT_SEQUENCE = 0xffffffff
SIGHASH_DEFAULT = 0x00
SIGHASH_OUTPUT_MASK = 0x03
SIGHASH_INPUT_MASK = 0x80
ADVANCED_TRANSACTION_MARKER = 0x00
ADVANCED_TRANSACTION_FLAG = 0x01

class BufferWriter:
    def __init__(self, capacity):
        self.buffer = bytearray(capacity)
        self.offset = 0

    @staticmethod
    def with_capacity(capacity):
        return BufferWriter(capacity)

    def write_slice(self, data):
        length = len(data)
        self.buffer[self.offset:self.offset+length] = data
        self.offset += length

    def write_uint32(self, value):
        self.buffer[self.offset:self.offset+4] = struct.pack('<I', value)
        self.offset += 4

    def write_uint64(self, value):
        self.buffer[self.offset:self.offset+8] = struct.pack('<Q', value)
        self.offset += 8

    def write_int32(self, value):
        self.buffer[self.offset:self.offset+4] = struct.pack('<i', value)
        self.offset += 4

    def write_uint8(self, value):
        self.buffer[self.offset:self.offset+1] = struct.pack('<B', value)
        self.offset += 1

    def write_var_slice(self, data):
        length = len(data)
        self.write_var_int(length)
        self.write_slice(data)

    def write_var_int(self, value):
        if value < 0xfd:
            self.write_uint8(value)
        elif value <= 0xffff:
            self.write_uint8(0xfd)
            self.write_uint16(value)
        elif value <= 0xffffffff:
            self.write_uint8(0xfe)
            self.write_uint32(value)
        else:
            self.write_uint8(0xff)
            self.write_uint64(value)

    def write_uint16(self, value):
        self.buffer[self.offset:self.offset+2] = struct.pack('<H', value)
        self.offset += 2

    def end(self):
        return bytes(self.buffer[:self.offset])

def var_slice_size(script):
    length = len(script)
    return varint_size(length) + length

def varint_size(value):
    if value < 0xfd:
        return 1
    elif value <= 0xffff:
        return 3
    elif value <= 0xffffffff:
        return 5
    else:
        return 9

def add_psbt_pay_utxos(
        private_key: PrivateKey,
        psbt_in:List[PsbtIn],
        tx_in:List[TxIn],
        utxos:List[IUtxo],
        network: str):
    setup(network)
    total_input = 0
    for utxo in utxos:
        privkey = private_key
        if utxo.private_key_wif:
            privkey = PrivateKey(utxo.private_key_wif)

        pubkey = privkey.get_public_key().to_hex()
        if utxo.type == AddressType.P2WPKH:
            tx_in.append(
                TxIn(prev_out=OutPoint(tx_id=utxo.tx_id, vout=utxo.output_index),
                    sequence=MAX_SEQUENCE)
                )
            psbt_in.append(PsbtIn(witness_utxo=TxOut(value=utxo.satoshis,
                    script_pub_key=ScriptPubKey(bytes.fromhex(utxo.script)))
                ))
            total_input += utxo.satoshis

        elif utxo.type == AddressType.P2WSH:
            tx_in.append(
                TxIn(prev_out=OutPoint(tx_id=utxo.tx_id, vout=utxo.output_index),
                     sequence=MAX_SEQUENCE)
                )
            psbt_in.append(PsbtIn(witness_utxo=TxOut(value=utxo.satoshis,
                    script_pub_key=ScriptPubKey(bytes.fromhex(utxo.script))),
                ))
            total_input += utxo.satoshis

        elif utxo.type == AddressType.P2TR:
            tx_in.append(
                TxIn(prev_out=OutPoint(tx_id=utxo.tx_id, vout=utxo.output_index),
                     sequence=MAX_SEQUENCE)
                )
            psbt_in.append(PsbtIn(witness_utxo=TxOut(value=utxo.satoshis,
                    script_pub_key=ScriptPubKey(bytes.fromhex(utxo.script))),
                ))
            total_input += utxo.satoshis
        elif utxo.type == AddressType.P2TR_NOTE:
            tx_in.append(
                TxIn(prev_out=OutPoint(tx_id=utxo.tx_id, vout=utxo.output_index),
                     sequence=MAX_SEQUENCE)
                )
            p2note = generate_p2tr_note_info(pubkey, network)
            tap_leaf_p2pk_script = {
                p2note['p2pkP2TR']['witness']: (p2note['p2pkRedeem']['output'], 
                                                p2note['p2pkRedeem']['redeemVersion'])
            }

            psbt_in.append(PsbtIn(
                witness_utxo=TxOut(value=utxo.satoshis,
                    script_pub_key=ScriptPubKey(p2note['p2pkP2TR']['output'])),
                taproot_leaf_scripts=tap_leaf_p2pk_script,
            ))
            total_input += utxo.satoshis

    return total_input

def sign_psbt_input(private_key: PrivateKey, psbt: Psbt, input_index: int):
    input = psbt.inputs[input_index]
    pubkey = private_key.get_public_key().to_bytes()

    if input.taproot_leaf_scripts != {}:
        taproot_leaf_scripts = input.taproot_leaf_scripts
        preimage = b""
        for script in taproot_leaf_scripts:
            preimage += taproot_leaf_scripts[script][1].to_bytes(1, "little")

            script_len = len(taproot_leaf_scripts[script][0])
            if script_len < 0xfd:
                preimage += script_len.to_bytes(1, "little")
            elif script_len < 0xffff:
                preimage += b'\xfd' + script_len.to_bytes(2, "little")
            elif script_len < 0xffffffff:
                preimage += b'\xfe' + script_len.to_bytes(4, "little")
            else:
                preimage += b'\xff' + script_len.to_bytes(8, "little")
            preimage += taproot_leaf_scripts[script][0]
        vout_scripts = []
        values = []
        for vout in psbt.inputs:
            vout_scripts.append(vout.witness_utxo.script_pub_key.script)
            values.append(vout.witness_utxo.value)
        tapleaf_hash = tagged_hash(b"TapLeaf", preimage)
        hash_for_sig = hash_for_witness_v1(psbt.tx, input_index, vout_scripts,
                                           values, 0, tapleaf_hash, None)
        ex_key = CKey(private_key.to_bytes())
        signature = ex_key.sign_schnorr_no_tweak(hash_for_sig)
        psbt.inputs[input_index].taproot_script_spend_signatures = {pubkey:signature}
    else:
        in_utxos = []
        for psbt_input in psbt.inputs:
            in_utxos.append(psbt_input.witness_utxo)
        hash_for_sig = from_tx(in_utxos, psbt.tx, input_index, SIGHASH_ALL)
        ex_key = CKey(private_key.to_bytes())
        signature = ex_key.sign(hash_for_sig)
        psbt.inputs[input_index].partial_sigs[bytes(ex_key.pub)] = signature + bytes([SIGHASH_ALL])

def hash_for_witness_v1(tx:Tx,
                        in_index:int,
                        prev_out_scripts,
                        values,
                        hash_type,
                        leaf_hash=None,
                        annex=None):
    if len(values) != len(tx.vin) or len(prev_out_scripts) != len(tx.vin):
        raise ValueError('Must supply prevout script and value for all inputs')
    output_type = SIGHASH_ALL if hash_type == SIGHASH_DEFAULT else hash_type & SIGHASH_OUTPUT_MASK
    input_type = hash_type & SIGHASH_INPUT_MASK
    is_anyone_can_pay = input_type == SIGHASH_ANYONECANPAY
    is_none = output_type == SIGHASH_NONE
    is_single = output_type == SIGHASH_SINGLE
    hash_prevouts = EMPTY_BUFFER
    hash_amounts = EMPTY_BUFFER
    hash_script_pubkeys = EMPTY_BUFFER
    hash_sequences = EMPTY_BUFFER
    hash_outputs = EMPTY_BUFFER
    if not is_anyone_can_pay:
        buffer_writer = BufferWriter.with_capacity(36 * len(tx.vin))
        for tx_in in tx.vin:
            buffer_writer.write_slice(
                tx_in.prev_out.hash.to_bytes(length=32, byteorder='little',signed=False))
            buffer_writer.write_uint32(tx_in.prev_out.vout)
        hash_prevouts = sha256(buffer_writer.end())
        buffer_writer = BufferWriter.with_capacity(8 * len(tx.vin))
        for value in values:
            buffer_writer.write_uint64(value)
        hash_amounts = sha256(buffer_writer.end())
        buffer_writer = BufferWriter.with_capacity(
            sum(var_slice_size(script) for script in prev_out_scripts))
        for prev_out_script in prev_out_scripts:
            buffer_writer.write_var_slice(prev_out_script)
        hash_script_pubkeys = sha256(buffer_writer.end())
        buffer_writer = BufferWriter.with_capacity(4 * len(tx.vin))
        for tx_in in tx.vin:
            buffer_writer.write_uint32(tx_in.sequence)
        hash_sequences = sha256(buffer_writer.end())
    if not (is_none or is_single):
        tx_outs_size = sum(8 + var_slice_size(output.script_pub_key.script) for output in tx.vout)
        buffer_writer = BufferWriter.with_capacity(tx_outs_size)
        for out in tx.vout:
            buffer_writer.write_uint64(out.value)
            buffer_writer.write_var_slice(out.script_pub_key.script)
        hash_outputs = sha256(buffer_writer.end())
    elif is_single and in_index < len(tx.vout):
        output = tx.vout[in_index]
        buffer_writer = BufferWriter.with_capacity(8 + var_slice_size(output.script_pub_key.script))
        buffer_writer.write_uint64(output.value)
        buffer_writer.write_var_slice(output.script_pub_key.script)
        hash_outputs = sha256(buffer_writer.end())
    spend_type = (2 if leaf_hash else 0) + (1 if annex else 0)
    sig_msg_size = 174 - (49 if is_anyone_can_pay else 0) - (32 if is_none else 0)
    sig_msg_size = sig_msg_size + (32 if annex else 0) + (37 if leaf_hash else 0)
    sig_msg_writer = BufferWriter.with_capacity(sig_msg_size)
    sig_msg_writer.write_uint8(hash_type)
    sig_msg_writer.write_int32(tx.version)
    sig_msg_writer.write_uint32(tx.lock_time)
    sig_msg_writer.write_slice(hash_prevouts)
    sig_msg_writer.write_slice(hash_amounts)
    sig_msg_writer.write_slice(hash_script_pubkeys)
    sig_msg_writer.write_slice(hash_sequences)
    if not (is_none or is_single):
        sig_msg_writer.write_slice(hash_outputs)
    sig_msg_writer.write_uint8(spend_type)
    if is_anyone_can_pay:
        txinput = tx.vin[in_index]
        sig_msg_writer.write_slice(txinput.hash)
        sig_msg_writer.write_uint32(txinput.prev_out.vout)
        sig_msg_writer.write_uint64(values[in_index])
        sig_msg_writer.write_var_slice(prev_out_scripts[in_index])
        sig_msg_writer.write_uint32(txinput.sequence)
    else:
        sig_msg_writer.write_uint32(in_index)
    if annex:
        buffer_writer = BufferWriter.with_capacity(var_slice_size(annex))
        buffer_writer.write_var_slice(annex)
        sig_msg_writer.write_slice(sha256(buffer_writer.end()))
    if is_single:
        sig_msg_writer.write_slice(hash_outputs)
    if leaf_hash:
        sig_msg_writer.write_slice(leaf_hash)
        sig_msg_writer.write_uint8(0)
        sig_msg_writer.write_uint32(0xffffffff)
    buf_in = b'\x00' + sig_msg_writer.end()
    return tagged_hash(b'TapSighash', buf_in)

def create_coin_psbt(private_key: PrivateKey,
                     utxos: List[IUtxo],
                     to: List[ISendToAddress],
                     change: str,
                     network: str,
                     fee_rate: int,
                     fee: int = 1000):
    """
    Creates a Partially Signed Bitcoin Transaction (PSBT) for minting/sending coins.

    Args:
        private_key (PrivateKey): The private key used for signing the transaction.
        utxos (List[IUtxo]): The list of unspent transaction outputs (UTXOs) to use as inputs.
        to (List[ISendToAddress]): The list of addresses and amounts to send coins to.
        change (str): The address to receive the change (if any).
        network (str): The network to use (e.g., 'mainnet', 'testnet').
        fee_rate (int): The fee rate in satoshis per byte.
        fee (int, optional): The transaction fee in satoshis. Defaults to 1000.

    Returns:
        The transaction in Tx format of btclib.

    Raises:
        Exception: If there are insufficient funds or no change address is provided.
    """
    # Add UTXOs
    tx_out = []
    tx_in = []
    psbt_in = []
    psbt_out = []

    total_input = add_psbt_pay_utxos(private_key, psbt_in, tx_in, utxos, network)

    if len(to) == 1 and to[0].amount == total_input:
        value = int(total_input - fee)
        if value < MIN_SATOSHIS:
            raise Exception("Insufficient fund")
        psbt_out.append(PsbtOut())
        tx_out.append(TxOut(value, ScriptPubKey.from_address(to[0].address)))
    else:
        total_output = 0
        for item in to:
            psbt_out.append(PsbtOut())
            tx_out.append(TxOut(item.amount, ScriptPubKey.from_address(item.address)))
            total_output += item.amount

        value = int(total_input - total_output - fee)
        if value < 0:
            raise Exception("NoFund")
        if value > MIN_SATOSHIS:
            psbt_out.append(PsbtOut())
            tx_out.append(TxOut(value, ScriptPubKey.from_address(change)))


    psbt = Psbt(tx=Tx(version=2, lock_time=0, vin=tx_in, vout=tx_out),
                inputs=psbt_in,
                outputs=psbt_out,
                hd_key_paths={},
                version=0)

    # Sign inputs
    for i in range(len(psbt.inputs)):
        utxo = utxos[i]
        sign_psbt_input(
            PrivateKey.from_wif(utxo.private_key_wif) if utxo.private_key_wif else private_key,
            psbt,
            i)

    for psbt_input in psbt.inputs:
        if psbt_input.partial_sigs != {}:
            psbt_input.final_script_witness = witness.Witness([
                list(psbt_input.partial_sigs.values())[0],
                list(psbt_input.partial_sigs.keys())[0]])
        elif psbt_input.taproot_leaf_scripts != {}:
            psbt_input.final_script_witness = witness.Witness([
                list(psbt_input.taproot_script_spend_signatures.values())[0], 
                list(psbt_input.taproot_leaf_scripts.values())[0][0], 
                list(psbt_input.taproot_leaf_scripts.keys())[0]])
        psbt_input.partial_sigs = {}
        psbt_input.sig_hash_type = None
        psbt_input.redeem_script = b""
        psbt_input.witness_script = b""
        psbt_input.hd_key_paths = {}

        psbt_input.taproot_script_spend_signatures = {}
        psbt_input.taproot_leaf_scripts = {}

    return extract_tx(psbt)


def create_p2tr_note_psbt(private_key,
                          note_payload: NotePayload,
                          note_utxos: List[IUtxo],
                          pay_utxos: List[IUtxo],
                          to_addresses: List[ISendToAddress],
                          change: str,
                          network: str,
                          fee_rate: int,
                          fee: int = 1000):

    pubkey = private_key.get_public_key().to_hex()
    p2note = generate_p2tr_note_info(pubkey, network)
    tap_leaf_note_script = {
        p2note['noteP2TR']['witness']: (
            p2note['noteRedeem']['output'],
            p2note['noteRedeem']['redeemVersion']
        )
    }

    tap_leaf_p2pk_script = {
        p2note['p2pkP2TR']['witness']: (
            p2note['p2pkRedeem']['output'],
            p2note['p2pkRedeem']['redeemVersion']
            )
    }

    total_input = 0
    psbt_in = []
    tx_in = []
    # Add note UTXOs to PSBT
    for i, note_utxo in enumerate(note_utxos):
        if i == 0:
            script = p2note['noteP2TR']['output'].hex()
            tap_leaf_script = tap_leaf_note_script
        else:
            script = p2note['p2pkP2TR']['output'].hex()
            tap_leaf_script = tap_leaf_p2pk_script

        tx_in.append(
            TxIn(prev_out=OutPoint(tx_id=note_utxo.tx_id, vout=note_utxo.output_index),
                 sequence=MAX_SEQUENCE))
        psbt_in.append(PsbtIn(
            witness_utxo=TxOut(value=note_utxo.satoshis, script_pub_key=ScriptPubKey(script)),
            taproot_leaf_scripts=tap_leaf_script,
        ))
        total_input += note_utxo.satoshis

    # Add payment UTXOs to PSBT
    total_input += add_psbt_pay_utxos(private_key, psbt_in, tx_in, pay_utxos, network)

    psbt_out = []
    tx_out = []
    # Add outputs
    total_output = 0
    for to in to_addresses:
        psbt_out.append(PsbtOut())
        tx_out.append(TxOut(to.amount, ScriptPubKey.from_address(to.address)))
        total_output += to.amount

    value = total_input - total_output - fee
    if value < 0:
        raise ValueError("NoFund")
    if value > MIN_SATOSHIS:
        psbt_out.append(PsbtOut())
        tx_out.append(TxOut(value, ScriptPubKey.from_address(change)))

    psbt = Psbt(tx=Tx(version=2, lock_time=note_payload.locktime, vin=tx_in, vout=tx_out),
                inputs=psbt_in, outputs=psbt_out, hd_key_paths={}, version=0)

    # Sign inputs
    for i, note_utxo in enumerate(note_utxos):
        if note_utxo.private_key_wif is not None:
            privkey = PrivateKey(note_utxo.private_key_wif)
        else:
            privkey = private_key
        sign_psbt_input(privkey, psbt, i)

    for i in range(len(note_utxos), len(psbt.inputs)):
        pay_utxo = pay_utxos[i - len(note_utxos)]
        if pay_utxo.private_key_wif is not None:
            privkey = PrivateKey(pay_utxo.private_key_wif)
        else:
            privkey = private_key
        sign_psbt_input(privkey, psbt, i)

    script_solution = [
        list(psbt.inputs[0].taproot_script_spend_signatures.values())[0],
        bytes.fromhex(note_payload.data0),
        bytes.fromhex(note_payload.data1),
        bytes.fromhex(note_payload.data2),
        bytes.fromhex(note_payload.data3),
        bytes.fromhex(note_payload.data4),
    ]
    script_solution.append(p2note['noteRedeem']['output'])
    script_solution.append(p2note['noteP2TR']['witness'])

    # Finalize PSBT
    psbt.inputs[0].final_script_witness = witness.Witness(script_solution)
    psbt.inputs[0].taproot_script_spend_signatures = {}
    psbt.inputs[0].taproot_leaf_scripts = {}
    psbt.inputs[0].partial_sigs = {}
    psbt.inputs[0].sig_hash_type = None
    psbt.inputs[0].redeem_script = b""
    psbt.inputs[0].witness_script = b""
    psbt.inputs[0].hd_key_paths = {}

    for i in range(1, len(psbt.inputs)):
        if (psbt.inputs[i].partial_sigs != {}):
            psbt.inputs[i].final_script_witness = witness.Witness([
                list(psbt.inputs[i].partial_sigs.values())[0],
                list(psbt.inputs[i].partial_sigs.keys())[0]])
        elif psbt.inputs[i].taproot_leaf_scripts != {}:
            psbt.inputs[i].final_script_witness = witness.Witness([
                list(psbt.inputs[i].taproot_script_spend_signatures.values())[0], 
                list(psbt.inputs[i].taproot_leaf_scripts.values())[0][0], 
                list(psbt.inputs[i].taproot_leaf_scripts.keys())[0]])
            
        psbt.inputs[i].partial_sigs = {}
        psbt.inputs[i].sig_hash_type = None
        psbt.inputs[i].redeem_script = b""
        psbt.inputs[i].witness_script = b""
        psbt.inputs[i].hd_key_paths = {}

        psbt.inputs[i].taproot_script_spend_signatures = {}
        psbt.inputs[i].taproot_leaf_scripts = {}

    return extract_tx(psbt)

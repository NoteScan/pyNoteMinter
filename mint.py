from utils import string_to_hexstring

def mint_token(wallet, tick, amount, bitwork='20', fee_rate=None):
    note_note = None
    pay_notes = None
    result = None

    mint_data = {
        'p': "n20",
        'op': "mint",
        'tick': tick,
        'amt': amount,
    }

    bitwork = string_to_hexstring(bitwork)

    payload = wallet.build_n20_payload(mint_data)
    setattr(payload, "locktime", 0)
    to_address = wallet.current_account.token_address.address

    try:
        tx = wallet.build_n20_payload_transaction(
            payload,
            to_address,
            note_note,
            pay_notes,
            fee_rate,
            bitwork)
        if tx:
            result = wallet.broadcast_transaction(tx)
            return result
    except Exception as error:
        return {
            'success': False,
            'error': str(error),
        }

    return {
        'success': False,
        'error': "Failed to mint NotePow token",
    }

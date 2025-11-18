import hashlib
import hmac
import secrets
import math

# --- SETTINGS ---
SLOT_WIDTH = 0.1
NUM_SLOTS = 10
START_DELAY = 5.0 #  5s for network jitter
PACKET_SIZE = 128 # MTU size for monero p2p 

class GhostNode_Research_v15:
    def __init__(self, alias):
        self.alias = alias
        self.node_secret = secrets.token_bytes(32)

    # manual poisson because i dont want use numpy 
    def _get_k_value(self, lam=2.0):
        L = math.exp(-lam)
        p = 1.0
        k = 0
        while p > L:
            k += 1
            # secrets is slow but we need cryptographically secure here
            p *= (secrets.randbelow(10**9) / 10**9)
        return max(1, k - 1)

    # derive epoch key so identity is hiden
    def _get_epoch_key(self, block_hash):
        # ill use sha256 for the hkdf extract/expand
        # simplified version because i dont want more extra dependencies
        h = hmac.new(block_hash.encode(), self.node_secret, hashlib.sha256).digest()
        return hmac.new(h, b"ghost-v15-info", hashlib.sha256).digest()

    def generate_traffic(self, epoch_id, prev_hash):
        key = self._get_epoch_key(prev_hash)
        p_count = self._get_k_value(2.0) # lam=2 is good for noise
        
        batch = []
        for i in range(p_count):
            # 1. the commit
            proof_val = b"OK_VDF"
            salt_val = secrets.token_bytes(32)

            # C = H(Proof + Salt + Epoch + Index)
            h = hashlib.sha256()
            h.update(proof_val)
            h.update(salt_val)
            h.update(epoch_id.encode())
            h.update(str(i).encode())
            commitment = h.digest()

            # 2. timing logic (determin istic slots)
            label = f"slot_{i}".encode()
            entropy = hmac.new(key, label, hashlib.sha256).digest()

            # pick slot from first 4 byte of hmac
            raw_val = int.from_bytes(entropy[:4], 'little')
            slot_idx = raw_val % NUM_SLOTS

            # add jitter so ISP cant see sharp spike
            # 0 to 99ms
            jitter = secrets.randbelow(100) / 1000.0
            
            send_at = START_DELAY + (slot_idx * SLOT_WIDTH) + jitter

            # 3. build the blob
            # fill with noise first so length is always 128
            packet = bytearray(secrets.token_bytes(PACKET_SIZE))
            
            nonce = secrets.token_bytes(12)
            
            # ill use manual slice because i want be sure where bytes go
            packet[0:12] = nonce
            packet[12:44] = commitment

            batch.append({
                'time': send_at,
                'blob': bytes(packet),
                'info': (proof_val, salt_val, i)
            })
            
        return batch

# --- Test run ---
if __name__ == "__main__":
    test_node = GhostNode_Research_v15("Alpha-Node-PY")
    eid = "ep_100_test"
    b_hash = "0000abc_fake_hash"

    pulses = test_node.generate_traffic(eid, b_hash)

    print(f"DEBUG: count={len(pulses)} pulses out")
    for p in pulses:
        # print first few bytes of commit to check
        print(f" -> time={p['time']:.4f} | commit={p['blob'][12:18].hex()}...")
        
        # --- TODO: REMOVE ---
        # check if local verify is still work
        proof, salt, idx = p['info']
        h_check = hashlib.sha256()
        h_check.update(proof)
        h_check.update(salt)
        h_check.update(eid.encode())
        h_check.update(str(idx).encode())
        v_res = h_check.digest()

        if v_res == p['blob'][12:44]:
            print("    (local verify: ok)")
        else:
            print("    (local verify: ERR!! CHECK LOGS)")
        # ----------------------------------------
import base64
import hashlib
import hmac
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from werkzeug.security import generate_password_hash, check_password_hash
from database import init_db, get_connection


class SecureEVotingSystem:
    def __init__(self):
        init_db()

        self.candidates = ["Kandidat 1", "Kandidat 2", "Kandidat 3"]

        self.encryption_key = self.get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key)

        self.hmac_key = self.get_or_create_hmac_key()

        self.rsa_private_key = self.load_rsa_private_key()
        self.rsa_public_key = self.load_rsa_public_key()

        self.create_genesis_block()

    def get_setting(self, key):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()

        conn.close()

        if row:
            return row["value"]

        return None

    def set_setting(self, key, value):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, value)
        )

        conn.commit()
        conn.close()

    def get_or_create_encryption_key(self):
        key = os.environ.get("EVOTING_ENCRYPTION_KEY")

        if not key:
            raise ValueError("EVOTING_ENCRYPTION_KEY belum diatur di file .env")

        return key.encode()

    def get_or_create_hmac_key(self):
        key = os.environ.get("EVOTING_HMAC_KEY")

        if not key:
            raise ValueError("EVOTING_HMAC_KEY belum diatur di file .env")

        return bytes.fromhex(key)

    def load_rsa_private_key(self):
        key_b64 = os.environ.get("EVOTING_RSA_PRIVATE_KEY_B64")

        if not key_b64:
            raise ValueError("EVOTING_RSA_PRIVATE_KEY_B64 belum diatur di file .env")

        private_key_pem = base64.b64decode(key_b64.encode())

        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

        return private_key

    def load_rsa_public_key(self):
        key_b64 = os.environ.get("EVOTING_RSA_PUBLIC_KEY_B64")

        if not key_b64:
            raise ValueError("EVOTING_RSA_PUBLIC_KEY_B64 belum diatur di file .env")

        public_key_pem = base64.b64decode(key_b64.encode())

        public_key = serialization.load_pem_public_key(
            public_key_pem
        )

        return public_key

    def sign_report_hash(self, report_hash):
        signature = self.rsa_private_key.sign(
            report_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        signature_b64 = base64.b64encode(signature).decode()

        return signature_b64

    def verify_report_signature(self, report_hash, signature_b64):
        try:
            signature = base64.b64decode(signature_b64.encode())

            self.rsa_public_key.verify(
                signature,
                report_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True

        except InvalidSignature:
            return False

        except Exception:
            return False

    @property
    def voters(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM voters")
        rows = cursor.fetchall()

        conn.close()

        data = {}

        for row in rows:
            data[row["voter_id"]] = {
                "name": row["name"],
                "has_voted": row["has_voted"],
                "created_at": row["created_at"],
                "failed_login_count": row["failed_login_count"],
                "locked_until": row["locked_until"]
            }

        return data

    @property
    def chain(self):
        return self.get_chain()

    def sha256_text(self, text):
        return hashlib.sha256(text.encode()).hexdigest()

    def sha256_bytes(self, data):
        return hashlib.sha256(data).hexdigest()

    def create_hmac(self, data):
        return hmac.new(self.hmac_key, data, hashlib.sha256).hexdigest()

    def create_block_hash(self, block):
        block_copy = block.copy()
        block_copy.pop("hash", None)

        block_string = json.dumps(block_copy, sort_keys=True).encode()
        return self.sha256_bytes(block_string)

    def row_to_block(self, row):
        return {
            "index": row["block_index"],
            "voter_hash": row["voter_hash"],
            "encrypted_vote": row["encrypted_vote"],
            "timestamp": row["timestamp"],
            "previous_hash": row["previous_hash"],
            "data_hmac": row["data_hmac"],
            "hash": row["hash"]
        }

    def get_chain(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM blocks ORDER BY block_index ASC")
        rows = cursor.fetchall()

        conn.close()

        return [self.row_to_block(row) for row in rows]

    def get_last_block(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM blocks ORDER BY block_index DESC LIMIT 1")
        row = cursor.fetchone()

        conn.close()

        if row:
            return self.row_to_block(row)

        return None

    def count_blocks(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) AS total FROM blocks")
        row = cursor.fetchone()

        conn.close()

        return row["total"]

    def insert_block(self, block):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO blocks (
                block_index,
                voter_hash,
                encrypted_vote,
                timestamp,
                previous_hash,
                data_hmac,
                hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            block["index"],
            block["voter_hash"],
            block["encrypted_vote"],
            block["timestamp"],
            block["previous_hash"],
            block["data_hmac"],
            block["hash"]
        ))

        conn.commit()
        conn.close()

    def create_genesis_block(self):
        if self.count_blocks() > 0:
            return

        genesis_block = {
            "index": 0,
            "voter_hash": "GENESIS",
            "encrypted_vote": "",
            "timestamp": time.ctime(),
            "previous_hash": "0",
            "data_hmac": "",
        }

        genesis_block["hash"] = self.create_block_hash(genesis_block)
        self.insert_block(genesis_block)

    def generate_voter_id(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT voter_id FROM voters")
        rows = cursor.fetchall()

        conn.close()

        max_number = 0

        for row in rows:
            voter_id = row["voter_id"]

            if voter_id.startswith("VTR-"):
                try:
                    number = int(voter_id.replace("VTR-", ""))
                    if number > max_number:
                        max_number = number
                except ValueError:
                    pass

        return f"VTR-{max_number + 1}"

    def register_voter(self, voter_name, pin):
        voter_id = self.generate_voter_id()
        token = os.urandom(8).hex()

        token_hash = self.sha256_text(token)
        pin_hash = generate_password_hash(pin)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO voters (
                voter_id,
                name,
                token_hash,
                pin_hash,
                has_voted,
                created_at,
                failed_login_count,
                locked_until
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            voter_id,
            voter_name,
            token_hash,
            pin_hash,
            0,
            time.ctime(),
            0,
            0
        ))

        conn.commit()
        conn.close()

        return voter_id, token

    def get_voter(self, voter_id):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM voters WHERE voter_id = ?", (voter_id,))
        row = cursor.fetchone()

        conn.close()

        return row

    def get_voter_by_token(self, token):
        token_hash = self.sha256_text(token)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM voters WHERE token_hash = ?",
            (token_hash,)
        )
        row = cursor.fetchone()

        conn.close()

        return row

    def verify_voter_login(self, token, pin):
        voter = self.get_voter_by_token(token)

        if voter is None:
            return False, "Token voting tidak ditemukan.", None

        if not voter["pin_hash"]:
            return False, "Data pemilih lama belum memiliki PIN. Silakan registrasi ulang.", None

        now = time.time()
        locked_until = voter["locked_until"] or 0

        if locked_until > now:
            remaining = int(locked_until - now)
            return False, f"Akun pemilih dikunci sementara. Coba lagi dalam {remaining} detik.", None

        stored_pin_hash = voter["pin_hash"]

        if stored_pin_hash.startswith("pbkdf2:") or stored_pin_hash.startswith("scrypt:"):
            pin_valid = check_password_hash(stored_pin_hash, pin)
        else:
            pin_hash_input = self.sha256_text(pin)
            pin_valid = hmac.compare_digest(pin_hash_input, stored_pin_hash)

            if pin_valid:
                new_secure_hash = generate_password_hash(pin)

                conn = get_connection()
                cursor = conn.cursor()

                cursor.execute(
                    "UPDATE voters SET pin_hash = ? WHERE voter_id = ?",
                    (new_secure_hash, voter["voter_id"])
                )

                conn.commit()
                conn.close()

        if not pin_valid:
            failed_login_count = voter["failed_login_count"] or 0
            failed_login_count += 1

            conn = get_connection()
            cursor = conn.cursor()

            if failed_login_count >= 5:
                lock_time = now + 300

                cursor.execute("""
                    UPDATE voters
                    SET failed_login_count = ?, locked_until = ?
                    WHERE voter_id = ?
                """, (
                    0,
                    lock_time,
                    voter["voter_id"]
                ))

                conn.commit()
                conn.close()

                return False, "PIN salah 5 kali. Akun pemilih dikunci sementara selama 5 menit.", None

            cursor.execute("""
                UPDATE voters
                SET failed_login_count = ?
                WHERE voter_id = ?
            """, (
                failed_login_count,
                voter["voter_id"]
            ))

            conn.commit()
            conn.close()

            sisa = 5 - failed_login_count
            return False, f"PIN rahasia salah. Sisa percobaan: {sisa}", None

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE voters
            SET failed_login_count = ?, locked_until = ?
            WHERE voter_id = ?
        """, (
            0,
            0,
            voter["voter_id"]
        ))

        conn.commit()
        conn.close()

        return True, "Login pemilih berhasil.", voter["voter_id"]

    def cast_vote_authenticated(self, voter_id, candidate):
        voter = self.get_voter(voter_id)

        if voter is None:
            return False, "Data pemilih tidak ditemukan."

        if candidate not in self.candidates:
            return False, "Kandidat tidak valid."

        if voter["has_voted"] == 1:
            return False, "Pemilih sudah pernah melakukan voting."

        vote_data = {
            "candidate": candidate,
            "timestamp": time.ctime()
        }

        vote_json = json.dumps(vote_data).encode()
        encrypted_vote = self.cipher.encrypt(vote_json)
        vote_hmac = self.create_hmac(encrypted_vote)

        last_block = self.get_last_block()
        previous_hash = last_block["hash"]

        block = {
            "index": len(self.chain),
            "voter_hash": self.sha256_text(voter_id),
            "encrypted_vote": encrypted_vote.decode(),
            "timestamp": time.ctime(),
            "previous_hash": previous_hash,
            "data_hmac": vote_hmac
        }

        block["hash"] = self.create_block_hash(block)

        self.insert_block(block)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE voters SET has_voted = 1 WHERE voter_id = ?",
            (voter_id,)
        )

        conn.commit()
        conn.close()

        return True, "Voting berhasil disimpan secara aman."

    def verify_chain(self):
        chain = self.chain

        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]

            if current_block["previous_hash"] != previous_block["hash"]:
                return False, f"Manipulasi terdeteksi pada blok {i}: previous hash tidak cocok."

            current_hash = current_block["hash"]
            calculated_hash = self.create_block_hash(current_block)

            if current_hash != calculated_hash:
                return False, f"Manipulasi terdeteksi pada blok {i}: hash blok berubah."

            encrypted_vote = current_block["encrypted_vote"].encode()
            original_hmac = current_block["data_hmac"]
            calculated_hmac = self.create_hmac(encrypted_vote)

            if not hmac.compare_digest(original_hmac, calculated_hmac):
                return False, f"Manipulasi terdeteksi pada blok {i}: HMAC tidak valid."

        return True, "Seluruh data voting valid. Tidak ada manipulasi."

    def tally_votes(self):
        result = {candidate: 0 for candidate in self.candidates}
        invalid_votes = []

        chain = self.chain

        for i in range(1, len(chain)):
            block = chain[i]
            previous_block = chain[i - 1]

            is_valid = True
            reasons = []

            if block["previous_hash"] != previous_block["hash"]:
                is_valid = False
                reasons.append("previous hash tidak cocok")

            original_hash = block["hash"]
            calculated_hash = self.create_block_hash(block)

            if original_hash != calculated_hash:
                is_valid = False
                reasons.append("hash blok berubah")

            encrypted_vote = block["encrypted_vote"].encode()
            original_hmac = block["data_hmac"]
            calculated_hmac = self.create_hmac(encrypted_vote)

            if not hmac.compare_digest(original_hmac, calculated_hmac):
                is_valid = False
                reasons.append("HMAC tidak valid")

            try:
                decrypted_vote = self.cipher.decrypt(encrypted_vote)
                vote_data = json.loads(decrypted_vote.decode())
                candidate = vote_data.get("candidate", "Tidak diketahui")
            except Exception:
                candidate = "Data tidak bisa dibaca"
                is_valid = False
                reasons.append("data suara gagal didekripsi")

            if is_valid:
                if candidate in result:
                    result[candidate] += 1
            else:
                invalid_votes.append({
                    "block_index": block["index"],
                    "candidate": candidate,
                    "reason": ", ".join(reasons)
                })

        return result, invalid_votes

    def backup_original_vote(self, block):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO tamper_backups (
                block_index,
                original_encrypted_vote,
                restored,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            block["index"],
            block["encrypted_vote"],
            0,
            time.ctime()
        ))

        conn.commit()
        conn.close()

    def tamper_data_demo(self, source_candidate, target_candidate):
        if len(self.chain) <= 1:
            return False, "Belum ada data voting yang bisa dimanipulasi."

        if source_candidate not in self.candidates:
            return False, "Kandidat asal manipulasi tidak valid."

        if target_candidate not in self.candidates:
            return False, "Kandidat tujuan manipulasi tidak valid."

        if source_candidate == target_candidate:
            return False, "Kandidat asal dan kandidat tujuan tidak boleh sama."

        selected_block = None
        selected_vote_data = None

        for block in self.chain[1:]:
            try:
                original_hash = block["hash"]
                calculated_hash = self.create_block_hash(block)

                if original_hash != calculated_hash:
                    continue

                encrypted_vote = block["encrypted_vote"].encode()
                original_hmac = block["data_hmac"]
                calculated_hmac = self.create_hmac(encrypted_vote)

                if not hmac.compare_digest(original_hmac, calculated_hmac):
                    continue

                decrypted_vote = self.cipher.decrypt(encrypted_vote)
                vote_data = json.loads(decrypted_vote.decode())

                candidate_in_block = vote_data.get("candidate")

                if candidate_in_block == source_candidate:
                    selected_block = block
                    selected_vote_data = vote_data
                    break

            except Exception:
                continue

        if selected_block is None:
            return False, f"Tidak ada suara valid dari {source_candidate} yang bisa dimanipulasi."

        kandidat_awal = selected_vote_data["candidate"]

        self.backup_original_vote(selected_block)

        selected_vote_data["candidate"] = target_candidate
        selected_vote_data["timestamp"] = time.ctime()
        selected_vote_data["tampered_note"] = "Suara diubah untuk simulasi pengujian keamanan."

        new_vote_json = json.dumps(selected_vote_data).encode()
        new_encrypted_vote = self.cipher.encrypt(new_vote_json).decode()

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE blocks SET encrypted_vote = ? WHERE block_index = ?",
            (new_encrypted_vote, selected_block["index"])
        )

        conn.commit()
        conn.close()

        return True, f"Simulasi berhasil. Suara pada blok {selected_block['index']} diubah dari {kandidat_awal} menjadi {target_candidate}. Data asli sudah dibackup."

    def restore_last_tamper_data(self):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM tamper_backups
            WHERE restored = 0
            ORDER BY id DESC
            LIMIT 1
        """)

        backup = cursor.fetchone()

        if backup is None:
            conn.close()
            return False, "Tidak ada data manipulasi yang perlu dikembalikan."

        cursor.execute("""
            UPDATE blocks
            SET encrypted_vote = ?
            WHERE block_index = ?
        """, (
            backup["original_encrypted_vote"],
            backup["block_index"]
        ))

        cursor.execute("""
            UPDATE tamper_backups
            SET restored = 1
            WHERE id = ?
        """, (
            backup["id"],
        ))

        conn.commit()
        conn.close()

        return True, f"Data pada blok {backup['block_index']} berhasil dikembalikan dari backup."

    def reset_voter_token(self, voter_id):
        voter = self.get_voter(voter_id)

        if voter is None:
            return False, "Data pemilih tidak ditemukan.", None

        new_token = os.urandom(8).hex()
        new_token_hash = self.sha256_text(new_token)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE voters
            SET token_hash = ?,
                failed_login_count = ?,
                locked_until = ?
            WHERE voter_id = ?
        """, (
            new_token_hash,
            0,
            0,
            voter_id
        ))

        conn.commit()
        conn.close()

        return True, f"Token pemilih {voter_id} berhasil direset. Token lama sudah tidak berlaku.", new_token

    def reset_voter_security_status(self, voter_id):
        voter = self.get_voter(voter_id)

        if voter is None:
            return False, "Data pemilih tidak ditemukan."

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE voters
            SET failed_login_count = ?, locked_until = ?
            WHERE voter_id = ?
        """, (
            0,
            0,
            voter_id
        ))

        conn.commit()
        conn.close()

        return True, f"Status keamanan pemilih {voter_id} berhasil direset. Akun sudah aktif kembali."

    def add_audit_log(self, role, action, description, ip_address=None):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO audit_logs (
                role,
                action,
                description,
                ip_address,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            role,
            action,
            description,
            ip_address,
            time.ctime()
        ))

        conn.commit()
        conn.close()

    def get_audit_logs(self, limit=100):
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
        """, (
            limit,
        ))

        rows = cursor.fetchall()
        conn.close()

        logs = []

        for row in rows:
            logs.append({
                "id": row["id"],
                "role": row["role"],
                "action": row["action"],
                "description": row["description"],
                "ip_address": row["ip_address"],
                "created_at": row["created_at"]
            })

        return logs
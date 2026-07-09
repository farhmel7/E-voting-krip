from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from functools import wraps
from datetime import timedelta
import json
import csv
import io
import time
import hashlib
import hmac
import os
import secrets
import shutil
from dotenv import load_dotenv


load_dotenv()

from evoting_system import SecureEVotingSystem


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY belum diatur di file .env")

app.permanent_session_lifetime = timedelta(minutes=30)

system = SecureEVotingSystem()

ADMIN_USERNAME = "admin"

ADMIN_PASSWORD_SALT = "896f08c38fad047bc318e5b6ae11cb42"
ADMIN_PASSWORD_HASH = "b5b8e38bc0e497fe888b93dcf8bad0da5726c93ac04430ffe977523d1cafc0d9"

MAX_LOGIN_ATTEMPTS = 5
LOCK_TIME_SECONDS = 300

EVOTING_MODE = os.environ.get("EVOTING_MODE", "secure").lower()

VOTER_ACCESS_CODE = os.environ.get("VOTER_ACCESS_CODE")

if not VOTER_ACCESS_CODE:
    raise ValueError("VOTER_ACCESS_CODE belum diatur di file .env")

if EVOTING_MODE == "demo":
    ENABLE_TAMPER_DEMO = True
else:
    ENABLE_TAMPER_DEMO = False

login_attempts = {}


def create_database_backup(action_name):
    if not os.path.exists("backups"):
        os.makedirs("backups")

    if not os.path.exists("evoting.db"):
        return "Database belum tersedia"

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{action_name}_{timestamp}.db"
    backup_path = os.path.join("backups", backup_filename)

    shutil.copy2("evoting.db", backup_path)

    return backup_path


@app.context_processor
def inject_settings():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    return {
        "enable_tamper_demo": ENABLE_TAMPER_DEMO,
        "csrf_token": session["_csrf_token"]
    }


@app.before_request
def csrf_protection():
    if request.method == "POST":
        session_token = session.get("_csrf_token")
        form_token = request.form.get("csrf_token")

        if not session_token or not form_token or not hmac.compare_digest(session_token, form_token):
            flash("Permintaan tidak valid. CSRF token tidak cocok.", "error")
            return redirect(request.referrer or url_for("login"))


def get_ip_address():
    return request.remote_addr or "unknown"


def hash_admin_password(password):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        bytes.fromhex(ADMIN_PASSWORD_SALT),
        200000
    ).hex()


def verify_admin_password(password):
    input_hash = hash_admin_password(password)
    return hmac.compare_digest(input_hash, ADMIN_PASSWORD_HASH)


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("role"):
            flash("Silakan login terlebih dahulu.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Halaman ini hanya bisa diakses oleh admin.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def voter_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if session.get("role") != "voter":
            flash("Halaman ini hanya bisa diakses oleh pemilih.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        total_voters=len(system.voters),
        total_votes=len(system.chain) - 1,
        total_blocks=len(system.chain)
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        pin = request.form.get("pin", "").strip()
        access_code = request.form.get("access_code", "").strip()

        if not name:
            flash("Nama pemilih wajib diisi.", "error")
            return redirect(url_for("register"))

        if len(pin) < 4:
            flash("PIN minimal 4 digit atau karakter.", "error")
            return redirect(url_for("register"))

        if not access_code:
            flash("Kode akses pemilih wajib diisi.", "error")
            return redirect(url_for("register"))

        if not hmac.compare_digest(access_code, VOTER_ACCESS_CODE):
            system.add_audit_log(
                "voter",
                "REGISTRASI_DITOLAK",
                "Percobaan registrasi ditolak karena kode akses pemilih tidak valid.",
                get_ip_address()
            )

            flash("Kode akses pemilih tidak valid. Registrasi ditolak.", "error")
            return redirect(url_for("register"))

        voter_id, token = system.register_voter(name, pin)

        system.add_audit_log(
            "voter",
            "REGISTRASI",
            f"Pemilih baru berhasil registrasi dengan ID {voter_id}.",
            get_ip_address()
        )

        return render_template(
            "register.html",
            voter_id=voter_id,
            token=token,
            name=name
        )

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    ip_address = get_ip_address()
    now = time.time()

    if request.method == "POST":
        role = request.form.get("role", "").strip()

        if role == "admin":
            attempt_key = f"admin:{ip_address}"

            attempt_data = login_attempts.get(attempt_key, {
                "count": 0,
                "locked_until": 0
            })

            if attempt_data["locked_until"] > now:
                remaining = int(attempt_data["locked_until"] - now)
                flash(f"Terlalu banyak percobaan login admin. Coba lagi dalam {remaining} detik.", "error")
                return render_template("login.html")

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            if username == ADMIN_USERNAME and verify_admin_password(password):
                session_role_token = session.get("_csrf_token")

                session.clear()
                session.permanent = True
                session["_csrf_token"] = session_role_token or secrets.token_hex(32)
                session["role"] = "admin"

                if attempt_key in login_attempts:
                    del login_attempts[attempt_key]

                system.add_audit_log(
                    "admin",
                    "LOGIN_ADMIN",
                    "Admin berhasil login ke sistem.",
                    ip_address
                )

                flash("Login admin berhasil.", "success")
                return redirect(url_for("index"))

            system.add_audit_log(
                "admin",
                "LOGIN_ADMIN_GAGAL",
                "Percobaan login admin gagal.",
                ip_address
            )

            attempt_data["count"] += 1

            if attempt_data["count"] >= MAX_LOGIN_ATTEMPTS:
                attempt_data["locked_until"] = now + LOCK_TIME_SECONDS
                attempt_data["count"] = 0

                flash(
                    "Terlalu banyak percobaan login admin. Login admin dikunci sementara selama 5 menit.",
                    "error"
                )
            else:
                sisa = MAX_LOGIN_ATTEMPTS - attempt_data["count"]
                flash(f"Username atau password admin salah. Sisa percobaan: {sisa}", "error")

            login_attempts[attempt_key] = attempt_data
            return render_template("login.html")

        elif role == "voter":
            token = request.form.get("token", "").strip()
            pin = request.form.get("pin", "").strip()

            success, message, voter_id = system.verify_voter_login(token, pin)

            if success:
                session_role_token = session.get("_csrf_token")

                session.clear()
                session.permanent = True
                session["_csrf_token"] = session_role_token or secrets.token_hex(32)
                session["role"] = "voter"
                session["voter_id"] = voter_id

                system.add_audit_log(
                    "voter",
                    "LOGIN_PEMILIH",
                    f"Pemilih dengan ID {voter_id} berhasil login.",
                    ip_address
                )

                flash(message, "success")
                return redirect(url_for("index"))

            if "PIN salah 5 kali" in message:
                system.add_audit_log(
                    "voter",
                    "AKUN_PEMILIH_TERKUNCI",
                    message,
                    ip_address
                )
            elif "dikunci sementara" in message:
                system.add_audit_log(
                    "voter",
                    "LOGIN_PEMILIH_DITOLAK",
                    message,
                    ip_address
                )
            else:
                system.add_audit_log(
                    "voter",
                    "LOGIN_PEMILIH_GAGAL",
                    message,
                    ip_address
                )

            flash(message, "error")
            return render_template("login.html")

        else:
            flash("Pilih role login terlebih dahulu.", "error")
            return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    role = session.get("role", "unknown")
    voter_id = session.get("voter_id")

    if role == "admin":
        system.add_audit_log(
            "admin",
            "LOGOUT_ADMIN",
            "Admin logout dari sistem.",
            get_ip_address()
        )
    elif role == "voter":
        system.add_audit_log(
            "voter",
            "LOGOUT_PEMILIH",
            f"Pemilih dengan ID {voter_id} logout dari sistem.",
            get_ip_address()
        )

    session.clear()
    flash("Berhasil logout.", "success")
    return redirect(url_for("login"))


@app.route("/profile")
@voter_required
def profile():
    voter_id = session.get("voter_id")
    voter = system.get_voter(voter_id)

    if voter is None:
        session.clear()
        flash("Data pemilih tidak ditemukan. Silakan login ulang.", "error")
        return redirect(url_for("login"))

    return render_template(
        "profile.html",
        voter=voter
    )


@app.route("/candidates")
@login_required
def candidates():
    return render_template(
        "candidates.html",
        candidates=system.candidates
    )


@app.route("/vote", methods=["GET", "POST"])
@voter_required
def vote():
    voter_id = session.get("voter_id")
    voter = system.get_voter(voter_id)

    if voter is None:
        session.clear()
        flash("Data pemilih tidak ditemukan. Silakan login ulang.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        candidate = request.form.get("candidate", "").strip()

        success, message = system.cast_vote_authenticated(voter_id, candidate)

        if success:
            system.add_audit_log(
                "voter",
                "VOTING",
                f"Pemilih dengan ID {voter_id} berhasil melakukan voting.",
                get_ip_address()
            )

            flash(message, "success")
        else:
            system.add_audit_log(
                "voter",
                "VOTING_GAGAL",
                f"Pemilih dengan ID {voter_id} gagal voting: {message}",
                get_ip_address()
            )

            flash(message, "error")

        return redirect(url_for("vote"))

    return render_template(
        "vote.html",
        candidates=system.candidates,
        voter=voter
    )


@app.route("/verify")
@admin_required
def verify():
    success, message = system.verify_chain()

    system.add_audit_log(
        "admin",
        "VERIFIKASI_BLOCKCHAIN",
        message,
        get_ip_address()
    )

    return render_template(
        "verify.html",
        success=success,
        message=message
    )


@app.route("/chain")
@admin_required
def chain():
    chain_json = json.dumps(system.chain, indent=4)

    system.add_audit_log(
        "admin",
        "LIHAT_BLOCKCHAIN",
        "Admin melihat data blockchain.",
        get_ip_address()
    )

    return render_template(
        "chain.html",
        chain_json=chain_json
    )


@app.route("/tally")
@admin_required
def tally():
    result, invalid_votes = system.tally_votes()

    system.add_audit_log(
        "admin",
        "HITUNG_SUARA",
        "Admin membuka halaman perhitungan suara.",
        get_ip_address()
    )

    return render_template(
        "tally.html",
        result=result,
        invalid_votes=invalid_votes
    )


@app.route("/export")
@admin_required
def export_report():
    result, invalid_votes = system.tally_votes()
    success, message = system.verify_chain()

    backup_path = create_database_backup("before_export")

    system.add_audit_log(
        "admin",
        "EXPORT_LAPORAN",
        f"Admin mengekspor laporan hasil e-voting dengan hash dan digital signature RSA. Backup dibuat: {backup_path}",
        get_ip_address()
    )

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["LAPORAN HASIL E-VOTING"])
    writer.writerow(["Status Verifikasi", message])
    writer.writerow([])
    writer.writerow(["HASIL SUARA SAH"])
    writer.writerow(["Nama Kandidat", "Jumlah Suara Sah"])

    for candidate, total in result.items():
        writer.writerow([candidate, total])

    if invalid_votes:
        writer.writerow([])
        writer.writerow(["DATA SUARA TERDETEKSI MANIPULASI"])
        writer.writerow(["Blok", "Kandidat Terbaca", "Alasan Tidak Valid"])

        for item in invalid_votes:
            writer.writerow([
                item["block_index"],
                item["candidate"],
                item["reason"]
            ])

    report_body = output.getvalue()
    report_hash = hashlib.sha256(report_body.encode()).hexdigest()
    report_signature = system.sign_report_hash(report_hash)

    writer.writerow([])
    writer.writerow(["HASH VERIFIKASI LAPORAN"])
    writer.writerow(["Algoritma Hash", "SHA-256"])
    writer.writerow(["Hash Laporan", report_hash])
    writer.writerow(["Algoritma Signature", "RSA-PSS + SHA-256"])
    writer.writerow(["Digital Signature", report_signature])
    writer.writerow(["Keterangan", "Hash dan digital signature digunakan untuk memeriksa keaslian laporan."])

    final_report = output.getvalue()

    response = Response(
        final_report,
        mimetype="text/csv"
    )

    response.headers["Content-Disposition"] = "attachment; filename=laporan_evoting.csv"

    return response


@app.route("/verify-report", methods=["GET", "POST"])
@admin_required
def verify_report():
    result_status = None
    result_message = None
    stored_hash = None
    calculated_hash = None
    stored_signature = None
    signature_status = None

    if request.method == "POST":
        report_file = request.files.get("report_file")

        if report_file is None or report_file.filename == "":
            flash("Pilih file laporan CSV terlebih dahulu.", "error")
            return redirect(url_for("verify_report"))

        try:
            file_content = report_file.read().decode("utf-8-sig")
            csv_rows = list(csv.reader(io.StringIO(file_content)))

            hash_section_index = None

            for index, row in enumerate(csv_rows):
                if row and row[0] == "HASH VERIFIKASI LAPORAN":
                    hash_section_index = index
                    break

            if hash_section_index is None:
                result_status = False
                result_message = "File laporan tidak memiliki bagian hash verifikasi."
            else:
                body_rows = csv_rows[:hash_section_index]

                while body_rows and len(body_rows[-1]) == 0:
                    body_rows.pop()

                for row in csv_rows[hash_section_index:]:
                    if row and row[0] == "Hash Laporan":
                        stored_hash = row[1].strip()

                    if row and row[0] == "Digital Signature":
                        stored_signature = row[1].strip()

                if not stored_hash:
                    result_status = False
                    result_message = "Hash laporan tidak ditemukan di dalam file."

                elif not stored_signature:
                    result_status = False
                    result_message = "Digital signature RSA tidak ditemukan di dalam file laporan."

                else:
                    output = io.StringIO()
                    writer = csv.writer(output)

                    for row in body_rows:
                        writer.writerow(row)

                    report_body = output.getvalue()
                    calculated_hash = hashlib.sha256(report_body.encode()).hexdigest()

                    hash_valid = hmac.compare_digest(stored_hash, calculated_hash)
                    signature_valid = system.verify_report_signature(
                        stored_hash,
                        stored_signature
                    )

                    signature_status = signature_valid

                    if hash_valid and signature_valid:
                        result_status = True
                        result_message = "Laporan valid. Isi file belum berubah dan digital signature RSA sah."

                    elif not hash_valid and signature_valid:
                        result_status = False
                        result_message = "Laporan tidak valid. Isi laporan berubah, meskipun signature asli masih terbaca."

                    elif hash_valid and not signature_valid:
                        result_status = False
                        result_message = "Laporan tidak valid. Hash cocok, tetapi digital signature RSA tidak sah."

                    else:
                        result_status = False
                        result_message = "Laporan tidak valid. Isi laporan dan digital signature tidak sesuai."

            system.add_audit_log(
                "admin",
                "VERIFIKASI_LAPORAN_RSA",
                result_message,
                get_ip_address()
            )

        except Exception as error:
            result_status = False
            result_message = f"Gagal memverifikasi laporan: {str(error)}"

            system.add_audit_log(
                "admin",
                "VERIFIKASI_LAPORAN_RSA_GAGAL",
                result_message,
                get_ip_address()
            )

    return render_template(
        "verify_report.html",
        result_status=result_status,
        result_message=result_message,
        stored_hash=stored_hash,
        calculated_hash=calculated_hash,
        stored_signature=stored_signature,
        signature_status=signature_status
    )


@app.route("/uji-manipulasi", methods=["GET", "POST"])
@admin_required
def uji_manipulasi():
    if not ENABLE_TAMPER_DEMO:
        pass  # demo manipulasi diaktifkan
        # # flash("Fitur uji manipulasi sedang dinonaktifkan.", "error")
        # # return redirect(url_for("verify"))

    if request.method == "POST":
        admin_password = request.form.get("admin_password", "").strip()
        source_candidate = request.form.get("source_candidate", "").strip()
        target_candidate = request.form.get("target_candidate", "").strip()

        if not verify_admin_password(admin_password):
            system.add_audit_log(
                "admin",
                "MANIPULASI_GAGAL",
                "Admin gagal menjalankan simulasi manipulasi karena password salah.",
                get_ip_address()
            )

            flash("Password admin salah. Simulasi manipulasi dibatalkan.", "error")
            return redirect(url_for("uji_manipulasi"))

        backup_path = create_database_backup("before_tamper")

        success, message = system.tamper_data_demo(source_candidate, target_candidate)

        if success:
            system.add_audit_log(
                "admin",
                "SIMULASI_MANIPULASI",
                f"{message} Backup dibuat: {backup_path}",
                get_ip_address()
            )

            flash(message, "success")
        else:
            system.add_audit_log(
                "admin",
                "SIMULASI_MANIPULASI_GAGAL",
                message,
                get_ip_address()
            )

            flash(message, "error")

        return redirect(url_for("verify"))

    return render_template(
        "uji_manipulasi.html",
        candidates=system.candidates
    )


@app.route("/restore-manipulasi", methods=["POST"])
@admin_required
def restore_manipulasi():
    admin_password = request.form.get("admin_password", "").strip()

    if not verify_admin_password(admin_password):
        system.add_audit_log(
            "admin",
            "RESTORE_GAGAL",
            "Admin gagal restore data karena password salah.",
            get_ip_address()
        )

        flash("Password admin salah. Restore data dibatalkan.", "error")
        return redirect(url_for("uji_manipulasi"))

    backup_path = create_database_backup("before_restore")

    success, message = system.restore_last_tamper_data()

    if success:
        system.add_audit_log(
            "admin",
            "RESTORE_MANIPULASI",
            f"{message} Backup dibuat: {backup_path}",
            get_ip_address()
        )

        flash(message, "success")
    else:
        system.add_audit_log(
            "admin",
            "RESTORE_MANIPULASI_GAGAL",
            message,
            get_ip_address()
        )

        flash(message, "error")

    return redirect(url_for("verify"))


@app.route("/cek-pemilih")
@admin_required
def cek_pemilih():
    safe_voters = []
    now = time.time()

    for voter_id, voter in system.voters.items():
        locked_until = voter.get("locked_until") or 0
        is_locked = locked_until > now

        if is_locked:
            remaining_seconds = int(locked_until - now)
        else:
            remaining_seconds = 0

        safe_voters.append({
            "voter_id": voter_id,
            "name": voter["name"],
            "has_voted": voter["has_voted"],
            "created_at": voter["created_at"],
            "failed_login_count": voter.get("failed_login_count", 0),
            "is_locked": is_locked,
            "remaining_seconds": remaining_seconds
        })

    system.add_audit_log(
        "admin",
        "LIHAT_DATA_PEMILIH",
        "Admin melihat daftar pemilih terdaftar beserta status keamanan akun.",
        get_ip_address()
    )

    return render_template(
        "cek_pemilih.html",
        voters=safe_voters,
        total_voters=len(safe_voters)
    )


@app.route("/reset-pemilih/<voter_id>", methods=["POST"])
@admin_required
def reset_pemilih(voter_id):
    success, message = system.reset_voter_security_status(voter_id)

    if success:
        system.add_audit_log(
            "admin",
            "RESET_KEAMANAN_PEMILIH",
            message,
            get_ip_address()
        )

        flash(message, "success")
    else:
        system.add_audit_log(
            "admin",
            "RESET_KEAMANAN_PEMILIH_GAGAL",
            message,
            get_ip_address()
        )

        flash(message, "error")

    return redirect(url_for("cek_pemilih"))


@app.route("/reset-token/<voter_id>", methods=["POST"])
@admin_required
def reset_token_pemilih(voter_id):
    success, message, new_token = system.reset_voter_token(voter_id)

    if success:
        system.add_audit_log(
            "admin",
            "RESET_TOKEN_PEMILIH",
            f"Admin mereset token pemilih {voter_id}. Token baru hanya ditampilkan sekali.",
            get_ip_address()
        )

        return render_template(
            "reset_token_result.html",
            voter_id=voter_id,
            message=message,
            new_token=new_token
        )

    system.add_audit_log(
        "admin",
        "RESET_TOKEN_PEMILIH_GAGAL",
        message,
        get_ip_address()
    )

    flash(message, "error")
    return redirect(url_for("cek_pemilih"))


@app.route("/hapus-pemilih/<voter_id>", methods=["POST"])
@admin_required
def hapus_pemilih(voter_id):
    backup_path = create_database_backup("before_delete_voter")

    success, message = system.delete_voter(voter_id)

    if success:
        system.add_audit_log(
            "admin",
            "HAPUS_AKUN_PEMILIH",
            f"{message} Backup dibuat: {backup_path}",
            get_ip_address()
        )

        flash(message, "success")
    else:
        system.add_audit_log(
            "admin",
            "HAPUS_AKUN_PEMILIH_GAGAL",
            message,
            get_ip_address()
        )

        flash(message, "error")

    return redirect(url_for("cek_pemilih"))


@app.route("/audit-log")
@admin_required
def audit_log():
    logs = system.get_audit_logs(limit=100)

    system.add_audit_log(
        "admin",
        "LIHAT_AUDIT_LOG",
        "Admin melihat riwayat audit log.",
        get_ip_address()
    )

    return render_template(
        "audit_log.html",
        logs=logs
    )


if __name__ == "__main__":
    app.run(debug=False, use_reloader=False)

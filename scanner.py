import requests
from urllib.parse import urlparse

# Daftar HTTP Security Headers yang diperiksa beserta bobot skor dan penjelasannya
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 20,
        "desc": "Memaksa browser hanya berkomunikasi menggunakan HTTPS (mencegah SSL Stripping).",
        "fix": "Tambahkan header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "weight": 25,
        "desc": "Mencegah serangan Cross-Site Scripting (XSS) dan injeksi data dengan membatasi sumber konten.",
        "fix": "Tambahkan header: Content-Security-Policy: default-src 'self';"
    },
    "X-Frame-Options": {
        "weight": 15,
        "desc": "Melindungi situs dari serangan Clickjacking dengan melarang halaman dimuat di dalam <iframe>.",
        "fix": "Tambahkan header: X-Frame-Options: DENY atau SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "desc": "Mencegah browser melakukan MIME-sniffing yang dapat memicu eksekusi file berbahaya.",
        "fix": "Tambahkan header: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "weight": 10,
        "desc": "Mengontrol seberapa banyak informasi referrer yang dikirim saat pengguna berpindah halaman.",
        "fix": "Tambahkan header: Referrer-Policy: strict-origin-when-cross-origin"
    }
}

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def calculate_grade(score):
    if score >= 85:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 55:
        return "C"
    elif score >= 40:
        return "D"
    return "F"

def run_security_audit(raw_url):
    target_url = normalize_url(raw_url)
    parsed = urlparse(target_url)
    findings = []
    score = 0

    try:
        headers_req = {"User-Agent": "MiniSecurityAuditor/1.0 (Educational Passive Scanner)"}
        response = requests.get(target_url, headers=headers_req, timeout=8, allow_redirects=True)
        resp_headers = response.headers
        status_code = response.status_code

        # 1. Cek Penggunaan HTTPS (Bobot: 15 Poin)
        if response.url.startswith("https://"):
            score += 15
            findings.append({
                "check": "Enkripsi HTTPS / SSL",
                "status": "PASS",
                "value": "Aktif (HTTPS)",
                "desc": "Koneksi ke situs web dienkripsi menggunakan protokol HTTPS.",
                "fix": "Pertahankan validitas sertifikat TLS/SSL."
            })
        else:
            findings.append({
                "check": "Enkripsi HTTPS / SSL",
                "status": "FAIL",
                "value": "Tidak Aktif (HTTP Plaintext)",
                "desc": "Data dikirim tanpa enkripsi dan rentan terhadap penyadapan (Man-in-the-Middle).",
                "fix": "Pasang sertifikat SSL/TLS (misalnya Let's Encrypt) dan arahkan seluruh trafik HTTP ke HTTPS."
            })

        # 2. Cek masing-masing HTTP Security Header (Total Bobot: 85 Poin)
        for header_name, meta in SECURITY_HEADERS.items():
            header_val = resp_headers.get(header_name)
            if header_val:
                score += meta["weight"]
                findings.append({
                    "check": f"Header: {header_name}",
                    "status": "PASS",
                    "value": header_val[:80] + ("..." if len(header_val) > 80 else ""),
                    "desc": meta["desc"],
                    "fix": "Konfigurasi sudah terpasang."
                })
            else:
                findings.append({
                    "check": f"Header: {header_name}",
                    "status": "WARN",
                    "value": "Tidak Ditemukan (Missing)",
                    "desc": meta["desc"],
                    "fix": meta["fix"]
                })

        # 3. Cek Kebocoran Informasi Server (Information Disclosure)
        server_banner = resp_headers.get("Server") or resp_headers.get("X-Powered-By")
        if server_banner:
            findings.append({
                "check": "Server Banner / Info Disclosure",
                "status": "INFO",
                "value": server_banner,
                "desc": "Header mengekspos jenis atau versi web server/framework yang digunakan.",
                "fix": "Sembunyikan versi detail server (contoh: matikan ServerTokens di Apache atau server_tokens off di Nginx)."
            })
        else:
            findings.append({
                "check": "Server Banner / Info Disclosure",
                "status": "PASS",
                "value": "Tersembunyi",
                "desc": "Server tidak mengekspos informasi versi perangkat lunak secara terbuka.",
                "fix": "Tidak perlu tindakan."
            })

        grade = calculate_grade(score)
        return {
            "success": True,
            "target_url": response.url,
            "status_code": status_code,
            "score": score,
            "grade": grade,
            "findings": findings
        }

    except requests.exceptions.SSLError:
        return {
            "success": False,
            "error": "Sertifikat SSL tidak valid atau kedaluwarsa (SSL Verification Failed)."
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": f"Gagal menghubungi server target: Pastikan URL aktif dan dapat diakses."
        }
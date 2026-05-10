"""
Blocking Mechanism — Stub (Userspace Architecture)

Pada arsitektur userspace murni, pemblokiran dilakukan langsung oleh
Nginx pada Layer 7 (HTTP 403 Forbidden). File ini dipertahankan untuk
backward compatibility tetapi tidak lagi mengirim perintah ke eBPF.

Semua keputusan BLOCK dikirim kembali ke Nginx via UDS,
dan Nginx yang mengeksekusi pemblokiran.
"""

# TTL defaults (milliseconds) per attack type — digunakan untuk logging
TTL_TABLE = {
    "SQL_INJECTION": 30000,
    "COMMAND_INJECTION": 30000,
    "XSS": 15000,
    "PATH_TRAVERSAL": 15000,
    "UNKNOWN_ATTACK": 10000,
    "NONE": 0,
}

DEFAULT_TTL_MS = 10000


def compute_ttl(attack_type):
    """Determine recommended TTL based on attack severity (for audit/logging)."""
    return TTL_TABLE.get(attack_type, DEFAULT_TTL_MS)

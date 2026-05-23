"""
FORGE-SEC Security Report
Genera el informe de seguridad junto al código compilado.
"""
from typing import List
from .ast_nodes import *


def generate_report(program: Program,
                    tc_errors: List[str],
                    tc_warnings: List[str]) -> str:
    lines = ["", "=" * 60,
             "FORGE-SEC — SECURITY REPORT",
             "=" * 60, ""]

    # Recopilar info del programa
    has_tainted_input = False
    has_db = False
    has_session = False
    has_crypto = False
    has_log = False
    mutant_endpoints = []
    uses_sanitize = False
    has_secret = False

    def scan_expr(e):
        nonlocal has_db, has_session, has_crypto, has_log, uses_sanitize, has_secret
        if isinstance(e, DbFindOne) or isinstance(e, DbQuery):
            has_db = True
        if isinstance(e, SessionSet) or isinstance(e, SessionGet):
            has_session = True
        if isinstance(e, CryptoVerifyHash) or isinstance(e, CryptoHash):
            has_crypto = True
        if isinstance(e, LogWrite):
            has_log = True
        if isinstance(e, SanitizeCall):
            uses_sanitize = True

    def scan_stmt(s):
        if isinstance(s, LetStmt): scan_expr(s.value)
        elif isinstance(s, ReturnStmt): scan_expr(s.value)
        elif isinstance(s, ExprStmt): scan_expr(s.expr)
        elif isinstance(s, IfStmt):
            scan_expr(s.condition)
            for st in s.then_body: scan_stmt(st)
            if s.else_body:
                for st in s.else_body: scan_stmt(st)

    for decl in program.declarations:
        if isinstance(decl, WebApp):
            for ep in decl.endpoints:
                if ep.input_fields:
                    has_tainted_input = True
                if ep.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
                    mutant_endpoints.append(f"{ep.method} {ep.path}")
                for stmt in ep.body:
                    scan_stmt(stmt)
                for f in ep.input_fields:
                    if f.type_.wrapper == 'Secret':
                        has_secret = True
        elif isinstance(decl, FnDecl):
            for stmt in decl.body:
                scan_stmt(stmt)

    # Tabla de vulnerabilidades
    lines.append("Vulnerabilidades cubiertas:")
    lines.append("")

    vuln_ok  = "  ✅"
    vuln_na  = "  ➖"

    lines.append(f"{vuln_ok}  SQL Injection — Tainted<T> bloqueado en queries; prepared statements automáticos")

    if mutant_endpoints:
        lines.append(f"{vuln_ok}  CSRF — Token automático en: {', '.join(mutant_endpoints)}")
    else:
        lines.append(f"{vuln_na}  CSRF — No hay endpoints mutantes (GET only)")

    lines.append(f"{vuln_ok}  XSS — sanitize() genera HtmlSafe; ForgeSec_Html::safe() disponible")

    if has_crypto:
        lines.append(f"{vuln_ok}  Timing Attack — hash_equals() en comparaciones de credenciales")
    else:
        lines.append(f"{vuln_na}  Timing Attack — No se detectaron comparaciones de credenciales")

    if has_secret:
        lines.append(f"{vuln_ok}  Exposición de secretos — Secret<T> verificado en tipo checker")
    else:
        lines.append(f"{vuln_na}  Secret<T> — No usado en este módulo")

    lines.append(f"{vuln_ok}  Stack traces — Error interno: nunca al exterior (forge_error())")
    lines.append(f"{vuln_ok}  Path Traversal — fs.* requiere Trusted<Path> (sistema de tipos)")

    lines.append("")

    # Políticas detectadas
    policy_names = set()
    for decl in program.declarations:
        if isinstance(decl, WebApp):
            for ep in decl.endpoints:
                for p in ep.policies:
                    policy_names.add(p.name)

    if policy_names:
        lines.append("Políticas activas:")
        for p in sorted(policy_names):
            if p == 'RateLimit':
                lines.append(f"  ✅  Rate Limiting — implementado en RateLimiter")
            elif p == 'BruteForceProtection':
                lines.append(f"  ✅  Brute Force Protection — bloqueo tras 10 intentos")
            else:
                lines.append(f"  ✅  {p}")
        lines.append("")

    # Errores / advertencias del type checker
    if tc_errors:
        lines.append("Errores de seguridad (compilación bloqueada):")
        for e in tc_errors:
            lines.append(f"  {e}")
        lines.append("")

    if tc_warnings:
        lines.append("Advertencias:")
        for w in tc_warnings:
            lines.append(f"  {w}")
        lines.append("")

    if not tc_errors and not tc_warnings:
        lines.append("  ✅  Sin errores ni advertencias de seguridad")
        lines.append("")

    lines.append("=" * 60)
    lines.append("")
    return '\n'.join(lines)

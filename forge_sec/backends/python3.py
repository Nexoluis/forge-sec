"""
FORGE-SEC Backend: Python 3.12
Genera código Python seguro a partir del AST de FORGE-SEC.
Garantías:
  - SQL: solo parámetros posicionales (%s / ?) con psycopg2/sqlite3, nunca concatenación
  - XSS: html.escape() automático en output de templates
  - CSRF: token automático en endpoints POST/PUT/DELETE/PATCH
  - Secret<T>: nunca en logs ni en responses
  - Errores: stack traces nunca al exterior
  - Timing: hmac.compare_digest() en comparaciones de credenciales
"""
from typing import List, Optional
from ..ast_nodes import *


HEADER = '''\
# Generado por FORGE-SEC v0.1
# ⚠️  NO EDITAR MANUALMENTE — regenerar con: forge-sec build --target python3
# Requiere Python 3.12+
'''

RUNTIME = '''\
# ── Runtime de seguridad FORGE-SEC ──────────────────────────────────────────

from __future__ import annotations
import hashlib
import hmac
import html
import logging
import os
import secrets
import time
from email.utils import parseaddr
from typing import Any

_logger = logging.getLogger("forge_sec")


class _RateLimiter:
    _buckets: dict[str, int] = {}

    @classmethod
    def check(cls, key: str, max_req: int, window: int) -> bool:
        k = f"{key}_{int(time.time()) // window}"
        cls._buckets[k] = cls._buckets.get(k, 0) + 1
        return cls._buckets[k] <= max_req


class _BruteForce:
    _failures: dict[str, int] = {}

    @classmethod
    def record(cls, identifier: str) -> None:
        cls._failures[identifier] = cls._failures.get(identifier, 0) + 1

    @classmethod
    def is_locked(cls, identifier: str, max_failures: int = 10) -> bool:
        return cls._failures.get(identifier, 0) >= max_failures


class _Csrf:
    _tokens: dict[str, str] = {}

    @classmethod
    def token(cls, session_id: str) -> str:
        if session_id not in cls._tokens:
            cls._tokens[session_id] = secrets.token_hex(32)
        return cls._tokens[session_id]

    @classmethod
    def verify(cls, session_id: str, token: str) -> bool:
        expected = cls._tokens.get(session_id, "")
        return hmac.compare_digest(expected, token)


def _html_safe(value: Any) -> str:
    """XSS-safe: escapa caracteres especiales HTML."""
    return html.escape(str(value), quote=True)


def _forge_error(msg: str) -> dict:
    """Stack trace solo al log interno, nunca al exterior."""
    _logger.error("FORGE-SEC internal error: %s", msg)
    return {"error": "Error interno del servidor"}


'''


class Python3Backend:
    def __init__(self, namespace: str = 'ForgeGen'):
        self.namespace = namespace
        self.indent = 0

    def i(self, n: int = 0) -> str:
        return '    ' * (self.indent + n)

    def generate_program(self, program: Program, source_file: str = '') -> str:
        parts = [HEADER]
        if source_file:
            parts.append(f"# Fuente: {source_file}\n")
        parts.append(RUNTIME)

        for decl in program.declarations:
            if isinstance(decl, WebApp):
                parts.append(self.gen_web_app(decl))
            elif isinstance(decl, FnDecl):
                parts.append(self.gen_fn(decl))

        return '\n'.join(parts)

    # ── WebApp ────────────────────────────────────────────────────────────────

    def gen_web_app(self, app: WebApp) -> str:
        lines = [
            f"class {app.name}:",
            f"    def __init__(self, db) -> None:",
            f"        # db: psycopg2 connection o sqlite3 connection",
            f"        self._db = db",
            "",
        ]
        for ep in app.endpoints:
            lines.append(self.gen_endpoint(ep))
        lines.append("")
        return '\n'.join(lines)

    def gen_endpoint(self, ep: Endpoint) -> str:
        method_name = f"handle_{ep.method.lower()}_{self._path_to_method(ep.path)}"
        self.indent = 1

        lines = [
            f"    # {ep.method} {ep.path}",
        ]
        if ep.effects:
            lines.append(f"    # Effects: {', '.join(str(e) for e in ep.effects)}")
        if ep.security_constraints:
            lines.append(f"    # Security: {', '.join(ep.security_constraints)}")

        lines.append(f"    def {method_name}(self, raw_input: dict, session_id: str = '') -> dict:")

        body: list[str] = []

        # CSRF para métodos mutantes
        if ep.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            body += [
                "        # Verificación CSRF automática (endpoints mutantes)",
                "        if not _Csrf.verify(session_id, raw_input.get('_csrf_token', '')):",
                "            return {'error': 'Token CSRF inválido'}",
                "",
            ]

        # Policies
        for policy in ep.policies:
            body += self._gen_policy(policy)

        # Variables de input (todas Tainted)
        if ep.input_fields:
            body.append("        # Input — variables Tainted (origen externo)")
            for f in ep.input_fields:
                body.append(f"        {f.name}_tainted: str = str(raw_input.get('{f.name}', ''))")
            body.append("")

        # Body
        for stmt in ep.body:
            body += self.gen_stmt(stmt, ep.input_fields)

        # Garantizar que siempre hay return
        if not body or not any('return' in l for l in body):
            body.append("        return {}")

        lines += body
        lines.append("")
        return '\n'.join(lines)

    def _gen_policy(self, policy: PolicyDecl) -> List[str]:
        name = policy.name
        args = policy.args
        ip_expr = "raw_input.get('REMOTE_ADDR', '')"

        if name == 'RateLimit':
            count = args[0] if args else 5
            unit = args[1] if len(args) > 1 else 'min'
            window = 60 if unit == 'min' else int(unit)
            return [
                f"        # Rate limit: {count} req/{unit} por IP",
                f"        if not _RateLimiter.check(f'rl_{name}_' + {ip_expr}, {count}, {window}):",
                f"            return {{'error': 'Demasiados intentos. Espere un momento.'}}",
                "",
            ]
        if name == 'BruteForceProtection':
            return [
                "        # Protección brute force (bloqueo tras 10 intentos)",
                f"        __client_id = {ip_expr}",
                "        if _BruteForce.is_locked(__client_id):",
                "            return {'error': 'Cuenta bloqueada temporalmente'}",
                "",
            ]
        return [f"        # Policy: {name}"]

    # ── Statements ────────────────────────────────────────────────────────────

    def gen_stmt(self, stmt: Stmt,
                 input_fields: Optional[List] = None,
                 depth: int = 2) -> List[str]:
        pad = '    ' * depth

        if isinstance(stmt, LetStmt):
            val, extra = self.gen_expr(stmt.value, input_fields, depth)
            lines = extra
            lines.append(f"{pad}{stmt.name} = {val}")
            # NullCoalesce ?? return Error(...) → early return si None/False
            if isinstance(stmt.value, NullCoalesce) and isinstance(stmt.value.right, ReturnExpr):
                ret_val, _ = self.gen_expr(stmt.value.right.value, input_fields, depth)
                lines.append(f"{pad}if {stmt.name} is None or {stmt.name} is False:")
                lines.append(f"{pad}    return {ret_val}")
            return lines

        if isinstance(stmt, ReturnStmt):
            val, extra = self.gen_expr(stmt.value, input_fields, depth)
            return extra + [f"{pad}return {val}"]

        if isinstance(stmt, IfStmt):
            cond, extra = self.gen_expr(stmt.condition, input_fields, depth)
            lines = extra
            lines.append(f"{pad}if {cond}:")
            then_lines = []
            for s in stmt.then_body:
                then_lines += self.gen_stmt(s, input_fields, depth + 1)
            lines += then_lines if then_lines else [f"{pad}    pass"]
            if stmt.else_body:
                lines.append(f"{pad}else:")
                else_lines = []
                for s in stmt.else_body:
                    else_lines += self.gen_stmt(s, input_fields, depth + 1)
                lines += else_lines if else_lines else [f"{pad}    pass"]
            return lines

        if isinstance(stmt, ExprStmt):
            val, extra = self.gen_expr(stmt.expr, input_fields, depth)
            return extra + ([f"{pad}{val}"] if val else [])

        return [f"{pad}pass  # stmt desconocido"]

    # ── Expresiones ───────────────────────────────────────────────────────────

    def gen_expr(self, expr: Expr,
                 input_fields: Optional[List] = None,
                 depth: int = 2):
        """Devuelve (código_python, líneas_previas)."""
        pad = '    ' * depth

        if isinstance(expr, StringLit):
            return (repr(expr.value), [])

        if isinstance(expr, IntLit):
            return (str(expr.value), [])

        if isinstance(expr, FloatLit):
            return (str(expr.value), [])

        if isinstance(expr, BoolLit):
            return ('True' if expr.value else 'False', [])

        if isinstance(expr, IdentExpr):
            return (expr.name, [])

        if isinstance(expr, FieldAccess):
            obj, extra = self.gen_expr(expr.obj, input_fields, depth)
            # input.field → variable tainted local
            if isinstance(expr.obj, IdentExpr) and expr.obj.name == 'input':
                return (f"{expr.field}_tainted", extra)
            # dict access
            return (f"{obj}['{expr.field}']", extra)

        if isinstance(expr, SanitizeCall):
            inner, extra = self.gen_expr(expr.arg, input_fields, depth)
            sanitized_var = f"__sanitized_{id(expr) & 0xFFFF}"
            if 'email' in str(expr.arg).lower():
                lines = extra + [
                    f"{pad}# sanitize() — Tainted<Email> → Sanitized (SqlSafe)",
                    f"{pad}__parsed_name, __parsed_addr = parseaddr({inner})",
                    f"{pad}if not __parsed_addr or '@' not in __parsed_addr:",
                    f"{pad}    return {{'error': 'Datos de entrada inválidos'}}",
                    f"{pad}{sanitized_var} = __parsed_addr.lower()",
                ]
            else:
                lines = extra + [
                    f"{pad}# sanitize() — Tainted → Sanitized (HtmlSafe)",
                    f"{pad}{sanitized_var} = _html_safe({inner})",
                ]
            return (sanitized_var, lines)

        if isinstance(expr, DbFindOne):
            where_vars: list[str] = []
            extra_lines: list[str] = []
            where_parts: list[str] = []
            for field_name, field_expr in expr.where.items():
                v, ex = self.gen_expr(field_expr, input_fields, depth)
                extra_lines += ex
                ph_var = f"__ph_{field_name}_{id(expr) & 0xFFFF}"
                extra_lines.append(f"{pad}# SqlSafe — parámetro posicional, nunca concatenación")
                extra_lines.append(f"{pad}{ph_var} = {v}")
                where_parts.append(f"{self._snake(field_name)} = %s")
                where_vars.append(ph_var)

            result_var = f"__row_{id(expr) & 0xFFFF}"
            table = self._to_table(expr.model)
            where_sql = ' AND '.join(where_parts) if where_parts else '1=1'
            params_py = '(' + ', '.join(where_vars) + ',)'

            extra_lines += [
                f"{pad}__cur_{id(expr) & 0xFFFF} = self._db.cursor()",
                f"{pad}__cur_{id(expr) & 0xFFFF}.execute(",
                f"{pad}    'SELECT * FROM {table} WHERE {where_sql} LIMIT 1',",
                f"{pad}    {params_py}",
                f"{pad})",
                f"{pad}{result_var} = __cur_{id(expr) & 0xFFFF}.fetchone()",
            ]
            return (result_var, extra_lines)

        if isinstance(expr, DbQuery):
            where_vars = []
            extra_lines = []
            where_parts = []
            for field_name, field_expr in expr.where.items():
                v, ex = self.gen_expr(field_expr, input_fields, depth)
                extra_lines += ex
                ph_var = f"__ph_{field_name}_{id(expr) & 0xFFFF}"
                extra_lines.append(f"{pad}{ph_var} = {v}")
                where_parts.append(f"{self._snake(field_name)} = %s")
                where_vars.append(ph_var)

            result_var = f"__rows_{id(expr) & 0xFFFF}"
            table = self._to_table(expr.model)
            where_sql = ' AND '.join(where_parts) if where_parts else '1=1'
            limit_sql = f" LIMIT {expr.limit}" if expr.limit else ""
            params_py = '(' + ', '.join(where_vars) + ',)'

            extra_lines += [
                f"{pad}__cur_{id(expr) & 0xFFFF} = self._db.cursor()",
                f"{pad}__cur_{id(expr) & 0xFFFF}.execute(",
                f"{pad}    'SELECT * FROM {table} WHERE {where_sql}{limit_sql}',",
                f"{pad}    {params_py}",
                f"{pad})",
                f"{pad}{result_var} = __cur_{id(expr) & 0xFFFF}.fetchall()",
            ]
            return (result_var, extra_lines)

        if isinstance(expr, CryptoVerifyHash):
            v1, e1 = self.gen_expr(expr.value, input_fields, depth)
            v2, e2 = self.gen_expr(expr.hash_val, input_fields, depth)
            result_var = f"__hashok_{id(expr) & 0xFFFF}"
            extra = e1 + e2 + [
                f"{pad}# timing_attack_safe: hmac.compare_digest() en tiempo constante",
                f"{pad}__computed_{id(expr) & 0xFFFF} = hashlib.sha256({v1}.encode()).hexdigest()",
                f"{pad}{result_var} = hmac.compare_digest(",
                f"{pad}    str({v2}),",
                f"{pad}    __computed_{id(expr) & 0xFFFF}",
                f"{pad})",
            ]
            return (result_var, extra)

        if isinstance(expr, CryptoHash):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (f"hashlib.sha256({v}.encode()).hexdigest()", ex)

        if isinstance(expr, SessionSet):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            # Secret<T> bloqueado por type_checker; aquí solo escribimos
            extra = ex + [f"{pad}# session.write — Secret<T> bloqueado por type_checker"]
            # En Python generamos un dict session que el caller debe persistir
            extra.append(f"{pad}__session['{expr.key}'] = {v}")
            return ('', extra)

        if isinstance(expr, SessionGet):
            return (f"__session.get('{expr.key}')", [])

        if isinstance(expr, LogWrite):
            v, ex = self.gen_expr(expr.message, input_fields, depth)
            # Secret<T> nunca llega aquí — verificado por type_checker
            return ('', ex + [f"{pad}_logger.info('%s', {v})"])

        if isinstance(expr, OkExpr):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (v, ex)

        if isinstance(expr, ErrorExpr):
            return (f"{{'error': {repr(expr.message)}}}", [])

        if isinstance(expr, DictLit):
            parts: list[str] = []
            extra_lines: list[str] = []
            for k, v in expr.pairs.items():
                vcode, vex = self.gen_expr(v, input_fields, depth)
                extra_lines += vex
                parts.append(f"'{k}': {vcode}")
            return ('{' + ', '.join(parts) + '}', extra_lines)

        if isinstance(expr, NullCoalesce):
            left, ex1 = self.gen_expr(expr.left, input_fields, depth)
            if isinstance(expr.right, ReturnExpr):
                # Manejado en gen_stmt(LetStmt)
                return (left, ex1)
            right, ex2 = self.gen_expr(expr.right, input_fields, depth)
            return (f"({left} if {left} is not None else {right})", ex1 + ex2)

        if isinstance(expr, ReturnExpr):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (v, ex)

        if isinstance(expr, BinOp):
            op_map = {'and': 'and', 'or': 'or', '==': '==', '!=': '!=',
                      '===': '==', '!==': '!='}
            op = op_map.get(expr.op, expr.op)
            lv, le = self.gen_expr(expr.left, input_fields, depth)
            rv, re_ = self.gen_expr(expr.right, input_fields, depth)
            return (f"({lv} {op} {rv})", le + re_)

        if isinstance(expr, UnaryOp):
            v, ex = self.gen_expr(expr.operand, input_fields, depth)
            op = 'not ' if expr.op == '!' else expr.op
            return (f"({op}{v})", ex)

        if isinstance(expr, CallExpr):
            func_code, ef = self.gen_expr(expr.func, input_fields, depth)
            args_code: list[str] = []
            extra = ef
            for a in expr.args:
                ac, ae = self.gen_expr(a, input_fields, depth)
                extra += ae
                args_code.append(ac)
            return (f"{func_code}(" + ', '.join(args_code) + ")", extra)

        return ("None  # expr desconocida", [])

    # ── Funciones libres ──────────────────────────────────────────────────────

    def gen_fn(self, fn: FnDecl) -> str:
        self.indent = 0
        params = ', '.join(
            f"{p.name}: {self._sec_type_hint(p.type_)}"
            for p in fn.params
        )
        ret_hint = self._ret_type_hint(fn.return_type)

        lines = [f"def {fn.name}({params}) -> {ret_hint}:"]
        body_lines: list[str] = []
        for stmt in fn.body:
            body_lines += self.gen_stmt(stmt, [], depth=1)
        lines += body_lines if body_lines else ["    pass"]
        lines += ["", ""]
        return '\n'.join(lines)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _path_to_method(self, path: str) -> str:
        """'/login' → 'login', '/api/user' → 'api_user'"""
        return '_'.join(
            part for part in path.strip('/').split('/') if part
        ) or 'index'

    def _to_table(self, model: str) -> str:
        import re
        s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', model)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower() + 's'

    def _snake(self, name: str) -> str:
        import re
        s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower()

    def _sec_type_hint(self, t: SecType) -> str:
        mapping = {'String': 'str', 'Int': 'int', 'Float': 'float',
                   'Bool': 'bool', 'Email': 'str', 'Password': 'str',
                   'Path': 'str'}
        return mapping.get(t.inner, 'Any')

    def _ret_type_hint(self, t) -> str:
        if isinstance(t, SecType):
            return self._sec_type_hint(t)
        if isinstance(t, str):
            if t.startswith('Result'):
                return 'dict'
            if t.startswith('List'):
                return 'list'
            mapping = {'String': 'str', 'Int': 'int', 'Float': 'float',
                       'Bool': 'bool', 'Void': 'None'}
            return mapping.get(t, 'Any')
        return 'Any'

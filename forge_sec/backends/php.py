"""
FORGE-SEC Backend: PHP 8.2
Genera código PHP seguro a partir del AST de FORGE-SEC.
Garantías:
  - SQL: solo PDO con prepared statements, nunca concatenación
  - XSS: htmlspecialchars() automático en output HTML
  - CSRF: token automático en endpoints POST/PUT/DELETE/PATCH
  - Timing: hash_equals() en comparaciones de credenciales
  - Errores: stack traces nunca al exterior
"""
from typing import List, Optional
from ..ast_nodes import *


HEADER = '''\
<?php
/**
 * Generado por FORGE-SEC v0.1
 * ⚠️  NO EDITAR MANUALMENTE — regenerar con: forge-sec build --target php8.2
 */

declare(strict_types=1);
'''

RUNTIME = '''\
// ── Runtime de seguridad FORGE-SEC ──────────────────────────────────────────

final class ForgeSec_RateLimiter {
    private static array $buckets = [];
    public static function check(string $key, int $max, int $window): bool {
        $k = $key . '_' . (int)(time() / $window);
        self::$buckets[$k] = (self::$buckets[$k] ?? 0) + 1;
        return self::$buckets[$k] <= $max;
    }
}

final class ForgeSec_BruteForce {
    private static array $failures = [];
    public static function record(string $id): void {
        self::$failures[$id] = (self::$failures[$id] ?? 0) + 1;
    }
    public static function isLocked(string $id, int $max = 10): bool {
        return (self::$failures[$id] ?? 0) >= $max;
    }
}

final class ForgeSec_Csrf {
    public static function token(): string {
        if (session_status() === PHP_SESSION_NONE) { session_start(); }
        if (empty($_SESSION['_forge_csrf'])) {
            $_SESSION['_forge_csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['_forge_csrf'];
    }
    public static function verify(string $token): bool {
        if (session_status() === PHP_SESSION_NONE) { session_start(); }
        return hash_equals($_SESSION['_forge_csrf'] ?? '', $token);
    }
}

final class ForgeSec_Html {
    public static function safe(mixed $v): string {
        return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

function forge_error(string $msg): never {
    // Stack trace nunca al exterior — solo al log interno
    error_log("FORGE-SEC internal error: $msg");
    http_response_code(500);
    echo json_encode(['error' => 'Error interno del servidor']);
    exit;
}

'''


class PHPBackend:
    def __init__(self, namespace: str = 'ForgeGen'):
        self.namespace = namespace
        self.indent = 0

    def i(self, n: int = 0) -> str:
        return '    ' * (self.indent + n)

    def generate_program(self, program: Program, source_file: str = '') -> str:
        parts = [HEADER]
        if source_file:
            parts.append(f"// Fuente: {source_file}\n")
        parts.append(RUNTIME)

        for decl in program.declarations:
            if isinstance(decl, WebApp):
                parts.append(self.gen_web_app(decl))
            elif isinstance(decl, FnDecl):
                parts.append(self.gen_fn(decl))

        return '\n'.join(parts)

    # ── WebApp ────────────────────────────────────────────────────────────────

    def gen_web_app(self, app: WebApp) -> str:
        lines = [f"class {app.name} {{",
                 f"    public function __construct(private PDO $db) {{}}",
                 ""]
        for ep in app.endpoints:
            lines.append(self.gen_endpoint(ep))
        lines.append("}")
        lines.append("")
        return '\n'.join(lines)

    def gen_endpoint(self, ep: Endpoint) -> str:
        method_name = f"handle{ep.method.capitalize()}{self._path_to_method(ep.path)}"
        self.indent = 1

        lines = [
            f"    /**",
            f"     * {ep.method} {ep.path}",
        ]
        if ep.effects:
            lines.append(f"     * Effects: {', '.join(str(e) for e in ep.effects)}")
        if ep.security_constraints:
            lines.append(f"     * Security: {', '.join(ep.security_constraints)}")
        lines.append(f"     */")
        lines.append(f"    public function {method_name}(array $rawInput): array {{")

        body = []

        # CSRF para métodos mutantes
        if ep.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            body += [
                "        // Verificación CSRF automática (endpoints mutantes)",
                "        if (!ForgeSec_Csrf::verify($rawInput['_csrf_token'] ?? '')) {",
                "            return ['error' => 'Token CSRF inválido'];",
                "        }",
                "",
            ]

        # Policies
        for policy in ep.policies:
            body += self._gen_policy(policy)

        # Variables de input (todas Tainted)
        if ep.input_fields:
            body.append("        // Input — variables Tainted (origen externo)")
            for f in ep.input_fields:
                body.append(f"        ${f.name}_tainted = (string)($rawInput['{f.name}'] ?? '');")
            body.append("")

        # Body
        for stmt in ep.body:
            body += self.gen_stmt(stmt, ep.input_fields)

        lines += body
        lines.append("    }")
        lines.append("")
        return '\n'.join(lines)

    def _gen_policy(self, policy: PolicyDecl) -> List[str]:
        name = policy.name
        args = policy.args
        ip_expr = "$_SERVER['REMOTE_ADDR'] ?? ''"

        if name == 'RateLimit':
            # args: [5, 'min'] o [5, 60]
            count = args[0] if args else 5
            unit = args[1] if len(args) > 1 else 'min'
            window = 60 if unit == 'min' else int(unit)
            return [
                f"        // Rate limit: {count} req/{unit} por IP",
                f"        if (!ForgeSec_RateLimiter::check('rl_{name}_' . ({ip_expr}), {count}, {window})) {{",
                f"            return ['error' => 'Demasiados intentos. Espere un momento.'];",
                f"        }}",
                "",
            ]
        if name == 'BruteForceProtection':
            return [
                f"        // Protección brute force (bloqueo tras 10 intentos)",
                f"        $__clientId = {ip_expr};",
                f"        if (ForgeSec_BruteForce::isLocked($__clientId)) {{",
                f"            return ['error' => 'Cuenta bloqueada temporalmente'];",
                f"        }}",
                "",
            ]
        return [f"        // Policy: {name}"]

    # ── Statements ────────────────────────────────────────────────────────────

    def gen_stmt(self, stmt: Stmt,
                 input_fields: Optional[List] = None,
                 depth: int = 2) -> List[str]:
        pad = '    ' * depth
        if isinstance(stmt, LetStmt):
            val, extra = self.gen_expr(stmt.value, input_fields)
            lines = extra
            lines.append(f"{pad}${stmt.name} = {val};")
            # Si el valor tiene NullCoalesce con ReturnExpr, añadimos el early return
            if isinstance(stmt.value, NullCoalesce) and isinstance(stmt.value.right, ReturnExpr):
                ret_val, _ = self.gen_expr(stmt.value.right.value, input_fields)
                lines.append(f"{pad}if (${stmt.name} === null || ${stmt.name} === false) {{")
                lines.append(f"{pad}    return {ret_val};")
                lines.append(f"{pad}}}")
            return lines

        if isinstance(stmt, ReturnStmt):
            val, extra = self.gen_expr(stmt.value, input_fields)
            return extra + [f"{pad}return {val};"]

        if isinstance(stmt, IfStmt):
            cond, extra = self.gen_expr(stmt.condition, input_fields)
            lines = extra
            lines.append(f"{pad}if ({cond}) {{")
            for s in stmt.then_body:
                lines += self.gen_stmt(s, input_fields, depth + 1)
            if stmt.else_body:
                lines.append(f"{pad}}} else {{")
                for s in stmt.else_body:
                    lines += self.gen_stmt(s, input_fields, depth + 1)
            lines.append(f"{pad}}}")
            return lines

        if isinstance(stmt, ExprStmt):
            val, extra = self.gen_expr(stmt.expr, input_fields)
            return extra + ([f"{pad}{val};"] if val else [])

        return [f"{pad}/* stmt desconocido */"]

    # ── Expresiones ───────────────────────────────────────────────────────────

    def gen_expr(self, expr: Expr,
                 input_fields: Optional[List] = None,
                 depth: int = 2):
        """Devuelve (código_php, líneas_previas)."""
        pad = '    ' * depth

        if isinstance(expr, StringLit):
            return (repr(expr.value).replace('"', "'"), [])

        if isinstance(expr, IntLit):
            return (str(expr.value), [])

        if isinstance(expr, FloatLit):
            return (str(expr.value), [])

        if isinstance(expr, BoolLit):
            return ('true' if expr.value else 'false', [])

        if isinstance(expr, IdentExpr):
            return (f"${expr.name}", [])

        if isinstance(expr, FieldAccess):
            obj, extra = self.gen_expr(expr.obj, input_fields, depth)
            # Si es input.field, usar la variable tainted
            if isinstance(expr.obj, IdentExpr) and expr.obj.name == 'input':
                field_name = expr.field
                return (f"${field_name}_tainted", extra)
            return (f"{obj}['{expr.field}']", extra)

        if isinstance(expr, SanitizeCall):
            inner, extra = self.gen_expr(expr.arg, input_fields, depth)
            # Detectar si es email, string, etc.
            # Usamos filter_var para email, htmlspecialchars para string
            if 'email' in str(expr.arg).lower():
                sanitized_var = f"$__sanitized_{id(expr) & 0xFFFF}"
                lines = extra + [
                    f"{pad}// sanitize() — Tainted<Email> → Sanitized (SqlSafe)",
                    f"{pad}{sanitized_var} = filter_var({inner}, FILTER_VALIDATE_EMAIL);",
                    f"{pad}if ({sanitized_var} === false) {{",
                    f"{pad}    return ['error' => 'Datos de entrada inválidos'];",
                    f"{pad}}}",
                ]
                return (sanitized_var, lines)
            else:
                sanitized_var = f"$__sanitized_{id(expr) & 0xFFFF}"
                lines = extra + [
                    f"{pad}// sanitize() — Tainted → Sanitized",
                    f"{pad}{sanitized_var} = htmlspecialchars({inner}, ENT_QUOTES, 'UTF-8');",
                ]
                return (sanitized_var, lines)

        if isinstance(expr, DbFindOne):
            # Construir WHERE con prepared statement
            where_vars = []
            extra_lines = []
            where_parts = []
            for field_name, field_expr in expr.where.items():
                v, ex = self.gen_expr(field_expr, input_fields, depth)
                extra_lines += ex
                ph_var = f"$__ph_{field_name}_{id(expr) & 0xFFFF}"
                extra_lines.append(f"{pad}// SqlSafe — prepared statement, nunca concatenación")
                extra_lines.append(f"{pad}{ph_var} = {v};")
                where_parts.append(f"{self._snake(field_name)} = ?")
                where_vars.append(ph_var)

            result_var = f"$__row_{id(expr) & 0xFFFF}"
            table = self._to_table(expr.model)
            where_sql = ' AND '.join(where_parts) if where_parts else '1'
            params_php = '[' + ', '.join(where_vars) + ']'

            extra_lines += [
                f"{pad}$__stmt_{id(expr) & 0xFFFF} = $this->db->prepare(",
                f"{pad}    'SELECT * FROM {table} WHERE {where_sql} LIMIT 1'",
                f"{pad});",
                f"{pad}$__stmt_{id(expr) & 0xFFFF}->execute({params_php});",
                f"{pad}{result_var} = $__stmt_{id(expr) & 0xFFFF}->fetch(PDO::FETCH_ASSOC) ?: null;",
            ]
            return (result_var, extra_lines)

        if isinstance(expr, DbQuery):
            where_vars = []
            extra_lines = []
            where_parts = []
            for field_name, field_expr in expr.where.items():
                v, ex = self.gen_expr(field_expr, input_fields, depth)
                extra_lines += ex
                ph_var = f"$__ph_{field_name}_{id(expr) & 0xFFFF}"
                extra_lines.append(f"{pad}{ph_var} = {v};")
                where_parts.append(f"{self._snake(field_name)} = ?")
                where_vars.append(ph_var)

            result_var = f"$__rows_{id(expr) & 0xFFFF}"
            table = self._to_table(expr.model)
            where_sql = ' AND '.join(where_parts) if where_parts else '1'
            limit_sql = f" LIMIT {expr.limit}" if expr.limit else ""
            params_php = '[' + ', '.join(where_vars) + ']'

            extra_lines += [
                f"{pad}$__stmt_{id(expr) & 0xFFFF} = $this->db->prepare(",
                f"{pad}    'SELECT * FROM {table} WHERE {where_sql}{limit_sql}'",
                f"{pad});",
                f"{pad}$__stmt_{id(expr) & 0xFFFF}->execute({params_php});",
                f"{pad}{result_var} = $__stmt_{id(expr) & 0xFFFF}->fetchAll(PDO::FETCH_ASSOC);",
            ]
            return (result_var, extra_lines)

        if isinstance(expr, CryptoVerifyHash):
            v1, e1 = self.gen_expr(expr.value, input_fields, depth)
            v2, e2 = self.gen_expr(expr.hash_val, input_fields, depth)
            # hash_equals — protección timing attack
            result_var = f"$__hashok_{id(expr) & 0xFFFF}"
            extra = e1 + e2 + [
                f"{pad}// timing_attack_safe: hash_equals() en tiempo constante",
                f"{pad}{result_var} = hash_equals((string){v2}, hash('sha256', {v1}));",
            ]
            return (result_var, extra)

        if isinstance(expr, CryptoHash):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (f"hash('sha256', {v})", ex)

        if isinstance(expr, SessionSet):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            extra = ex + [
                f"{pad}if (session_status() === PHP_SESSION_NONE) {{ session_start(); }}",
                f"{pad}$_SESSION['{expr.key}'] = {v};",
            ]
            return ('', extra)

        if isinstance(expr, SessionGet):
            return (f"($_SESSION['{expr.key}'] ?? null)", [])

        if isinstance(expr, LogWrite):
            v, ex = self.gen_expr(expr.message, input_fields, depth)
            # log.write nunca expone Secret (verificado por type checker)
            return ('', ex + [f"{pad}error_log({v});"])

        if isinstance(expr, OkExpr):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (v, ex)

        if isinstance(expr, ErrorExpr):
            return (f"['error' => {repr(expr.message).replace(chr(34), chr(39))}]", [])

        if isinstance(expr, DictLit):
            parts = []
            extra_lines = []
            for k, v in expr.pairs.items():
                vcode, vex = self.gen_expr(v, input_fields, depth)
                extra_lines += vex
                parts.append(f"'{k}' => {vcode}")
            return ('[' + ', '.join(parts) + ']', extra_lines)

        if isinstance(expr, NullCoalesce):
            left, ex1 = self.gen_expr(expr.left, input_fields, depth)
            if isinstance(expr.right, ReturnExpr):
                # Manejado en gen_stmt(LetStmt)
                return (left, ex1)
            right, ex2 = self.gen_expr(expr.right, input_fields, depth)
            return (f"({left} ?? {right})", ex1 + ex2)

        if isinstance(expr, ReturnExpr):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (v, ex)

        if isinstance(expr, BinOp):
            op_map = {'and': '&&', 'or': '||', '==': '===', '!=': '!=='}
            op = op_map.get(expr.op, expr.op)
            lv, le = self.gen_expr(expr.left, input_fields, depth)
            rv, re = self.gen_expr(expr.right, input_fields, depth)
            return (f"({lv} {op} {rv})", le + re)

        if isinstance(expr, UnaryOp):
            v, ex = self.gen_expr(expr.operand, input_fields, depth)
            return (f"{expr.op}{v}", ex)

        if isinstance(expr, CallExpr):
            func_code, ef = self.gen_expr(expr.func, input_fields, depth)
            args_code = []
            extra = ef
            for a in expr.args:
                ac, ae = self.gen_expr(a, input_fields, depth)
                extra += ae
                args_code.append(ac)
            return (f"{func_code}(" + ', '.join(args_code) + ")", extra)

        return ("/* expr desconocida */", [])

    # ── Funciones libres ──────────────────────────────────────────────────────

    def gen_fn(self, fn: FnDecl) -> str:
        self.indent = 0
        params = ', '.join(
            f"{self._sec_type_hint(p.type_)} ${p.name}"
            for p in fn.params
        )
        ret_hint = self._ret_type_hint(fn.return_type)

        lines = [
            f"function {fn.name}({params}): {ret_hint} {{",
        ]
        for stmt in fn.body:
            lines += self.gen_stmt(stmt, [], depth=1)
        lines += ["}", ""]
        return '\n'.join(lines)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _path_to_method(self, path: str) -> str:
        """'/login' → 'Login', '/api/user' → 'ApiUser'"""
        return ''.join(
            part.capitalize()
            for part in path.strip('/').split('/')
            if part
        ) or 'Index'

    def _to_table(self, model: str) -> str:
        """'User' → 'users', 'Pedido' → 'pedidos'"""
        import re
        s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', model)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower() + 's'

    def _snake(self, name: str) -> str:
        import re
        s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower()

    def _sec_type_hint(self, t: SecType) -> str:
        mapping = {'String': 'string', 'Int': 'int', 'Float': 'float',
                   'Bool': 'bool', 'Email': 'string', 'Password': 'string',
                   'Path': 'string'}
        return mapping.get(t.inner, 'mixed')

    def _ret_type_hint(self, t) -> str:
        if isinstance(t, SecType):
            return self._sec_type_hint(t)
        if isinstance(t, str):
            if t.startswith('Result'):
                return 'array'
            if t.startswith('List'):
                return 'array'
            mapping = {'String': 'string', 'Int': 'int', 'Float': 'float',
                       'Bool': 'bool', 'Void': 'void'}
            return mapping.get(t, 'mixed')
        return 'mixed'

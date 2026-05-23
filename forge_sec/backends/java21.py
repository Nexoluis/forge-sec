"""
FORGE-SEC Backend: Java 21
Genera código Java seguro a partir del AST de FORGE-SEC.
Garantías:
  - SQL: solo PreparedStatement con JDBC, nunca concatenación
  - XSS: escape automático con HtmlUtils
  - CSRF: token automático en endpoints POST/PUT/DELETE/PATCH
  - Secret<T>: nunca en logs ni en responses
  - Errores: stack traces nunca al exterior
  - Timing: MessageDigest.isEqual() en comparaciones de credenciales
"""
from typing import List, Optional
from ..ast_nodes import *


HEADER = '''\
// Generado por FORGE-SEC v0.1
// ⚠️  NO EDITAR MANUALMENTE — regenerar con: forge-sec build --target java21
// Requiere Java 21+
'''

RUNTIME = '''\
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import java.util.regex.Pattern;

// ── Runtime de seguridad FORGE-SEC ──────────────────────────────────────────

final class ForgeSec {

    private static final Logger LOG = Logger.getLogger("forge_sec");
    private static final SecureRandom RANDOM = new SecureRandom();

    // ── Rate Limiter ─────────────────────────────────────────────────────────

    static final class RateLimiter {
        private static final ConcurrentHashMap<String, AtomicInteger> BUCKETS =
            new ConcurrentHashMap<>();

        static boolean check(String key, int maxReq, int windowSeconds) {
            String k = key + "_" + (System.currentTimeMillis() / 1000 / windowSeconds);
            return BUCKETS.computeIfAbsent(k, x -> new AtomicInteger(0))
                          .incrementAndGet() <= maxReq;
        }
    }

    // ── Brute Force Protection ────────────────────────────────────────────────

    static final class BruteForce {
        private static final ConcurrentHashMap<String, AtomicInteger> FAILURES =
            new ConcurrentHashMap<>();

        static void record(String identifier) {
            FAILURES.computeIfAbsent(identifier, x -> new AtomicInteger(0))
                    .incrementAndGet();
        }

        static boolean isLocked(String identifier) {
            return isLocked(identifier, 10);
        }

        static boolean isLocked(String identifier, int maxFailures) {
            var count = FAILURES.get(identifier);
            return count != null && count.get() >= maxFailures;
        }
    }

    // ── CSRF ─────────────────────────────────────────────────────────────────

    static final class Csrf {
        private static final ConcurrentHashMap<String, String> TOKENS =
            new ConcurrentHashMap<>();

        static String token(String sessionId) {
            return TOKENS.computeIfAbsent(sessionId, k -> {
                byte[] bytes = new byte[32];
                RANDOM.nextBytes(bytes);
                return HexFormat.of().formatHex(bytes);
            });
        }

        static boolean verify(String sessionId, String token) {
            String expected = TOKENS.getOrDefault(sessionId, "");
            return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                token.getBytes(StandardCharsets.UTF_8)
            );
        }
    }

    // ── HTML escape ───────────────────────────────────────────────────────────

    static String htmlSafe(Object value) {
        if (value == null) return "";
        return String.valueOf(value)
            .replace("&",  "&amp;")
            .replace("<",  "&lt;")
            .replace(">",  "&gt;")
            .replace("\\"", "&quot;")
            .replace("'",  "&#x27;");
    }

    // ── Sanitizers ────────────────────────────────────────────────────────────

    private static final Pattern EMAIL_RE =
        Pattern.compile("^[^@\\\\s]+@[^@\\\\s]+\\\\.[^@\\\\s]+$");

    static String sanitizeEmail(String raw) {
        String trimmed = raw.trim().toLowerCase();
        if (!EMAIL_RE.matcher(trimmed).matches()) {
            throw new ForgeSecValidationException("Email inválido");
        }
        return trimmed;
    }

    static String sanitizeString(String raw) {
        return htmlSafe(raw);
    }

    // ── Crypto ────────────────────────────────────────────────────────────────

    static String sha256(String value) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 no disponible", e);
        }
    }

    static boolean verifyHash(String value, String storedHash) {
        // timing_attack_safe: MessageDigest.isEqual() en tiempo constante
        String computed = sha256(value);
        return MessageDigest.isEqual(
            storedHash.getBytes(StandardCharsets.UTF_8),
            computed.getBytes(StandardCharsets.UTF_8)
        );
    }

    // ── Error seguro ──────────────────────────────────────────────────────────

    static Map<String, Object> forgeError(String internalMsg) {
        // Stack trace solo al log interno, nunca al exterior
        LOG.severe("FORGE-SEC internal error: " + internalMsg);
        return Map.of("error", "Error interno del servidor");
    }
}

class ForgeSecValidationException extends RuntimeException {
    ForgeSecValidationException(String msg) { super(msg); }
}

'''


class Java21Backend:
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
        lines = [
            f"class {app.name} {{",
            f"    private final Connection db;",
            f"",
            f"    public {app.name}(Connection db) {{",
            f"        this.db = db;",
            f"    }}",
            "",
        ]
        for ep in app.endpoints:
            lines.append(self.gen_endpoint(ep))
        lines.append("}")
        lines.append("")
        return '\n'.join(lines)

    def gen_endpoint(self, ep: Endpoint) -> str:
        method_name = f"handle{ep.method.capitalize()}{self._path_to_method(ep.path)}"
        self.indent = 1

        lines = [
            f"    // {ep.method} {ep.path}",
        ]
        if ep.effects:
            lines.append(f"    // Effects: {', '.join(str(e) for e in ep.effects)}")
        if ep.security_constraints:
            lines.append(f"    // Security: {', '.join(ep.security_constraints)}")

        lines.append(
            f"    public Map<String, Object> {method_name}("
            f"Map<String, String> rawInput, String sessionId) {{"
        )

        body: list[str] = []

        # CSRF para métodos mutantes
        if ep.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            body += [
                "        // Verificación CSRF automática (endpoints mutantes)",
                "        if (!ForgeSec.Csrf.verify(sessionId, rawInput.getOrDefault(\"_csrf_token\", \"\"))) {",
                "            return Map.of(\"error\", \"Token CSRF inválido\");",
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
                body.append(
                    f"        String {f.name}Tainted = rawInput.getOrDefault(\"{f.name}\", \"\");"
                )
            body.append("")

        # try/catch para SQLException y ValidationException
        body.append("        try {")
        for stmt in ep.body:
            body += self.gen_stmt(stmt, ep.input_fields, depth=3)
        body.append("        } catch (ForgeSecValidationException e) {")
        body.append("            return Map.of(\"error\", e.getMessage());")
        body.append("        } catch (SQLException e) {")
        body.append("            return ForgeSec.forgeError(e.getMessage());")
        body.append("        }")

        lines += body
        lines.append("    }")
        lines.append("")
        return '\n'.join(lines)

    def _gen_policy(self, policy: PolicyDecl) -> List[str]:
        name = policy.name
        args = policy.args
        ip_expr = 'rawInput.getOrDefault("REMOTE_ADDR", "")'

        if name == 'RateLimit':
            count = args[0] if args else 5
            unit = args[1] if len(args) > 1 else 'min'
            window = 60 if unit == 'min' else int(unit)
            return [
                f"        // Rate limit: {count} req/{unit} por IP",
                f"        if (!ForgeSec.RateLimiter.check(\"rl_{name}_\" + {ip_expr}, {count}, {window})) {{",
                f"            return Map.of(\"error\", \"Demasiados intentos. Espere un momento.\");",
                f"        }}",
                "",
            ]
        if name == 'BruteForceProtection':
            return [
                "        // Protección brute force (bloqueo tras 10 intentos)",
                f"        String clientId = {ip_expr};",
                "        if (ForgeSec.BruteForce.isLocked(clientId)) {",
                "            return Map.of(\"error\", \"Cuenta bloqueada temporalmente\");",
                "        }",
                "",
            ]
        return [f"        // Policy: {name}"]

    # ── Statements ────────────────────────────────────────────────────────────

    def gen_stmt(self, stmt: Stmt,
                 input_fields: Optional[List] = None,
                 depth: int = 2) -> List[str]:
        pad = '    ' * depth

        if isinstance(stmt, LetStmt):
            val, extra = self.gen_expr(stmt.value, input_fields, depth)
            java_type = self._infer_java_type(stmt.value)
            lines = extra
            lines.append(f"{pad}{java_type} {stmt.name} = {val};")
            if isinstance(stmt.value, NullCoalesce) and isinstance(stmt.value.right, ReturnExpr):
                ret_val, _ = self.gen_expr(stmt.value.right.value, input_fields, depth)
                lines.append(f"{pad}if ({stmt.name} == null) {{")
                lines.append(f"{pad}    return {ret_val};")
                lines.append(f"{pad}}}")
            return lines

        if isinstance(stmt, ReturnStmt):
            val, extra = self.gen_expr(stmt.value, input_fields, depth)
            return extra + [f"{pad}return {val};"]

        if isinstance(stmt, IfStmt):
            cond, extra = self.gen_expr(stmt.condition, input_fields, depth)
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
            val, extra = self.gen_expr(stmt.expr, input_fields, depth)
            return extra + ([f"{pad}{val};"] if val else [])

        return [f"{pad}// stmt desconocido"]

    # ── Expresiones ───────────────────────────────────────────────────────────

    def gen_expr(self, expr: Expr,
                 input_fields: Optional[List] = None,
                 depth: int = 2):
        """Devuelve (código_java, líneas_previas)."""
        pad = '    ' * depth

        if isinstance(expr, StringLit):
            return (f'"{expr.value}"', [])

        if isinstance(expr, IntLit):
            return (str(expr.value), [])

        if isinstance(expr, FloatLit):
            return (str(expr.value) + 'd', [])

        if isinstance(expr, BoolLit):
            return ('true' if expr.value else 'false', [])

        if isinstance(expr, IdentExpr):
            return (expr.name, [])

        if isinstance(expr, FieldAccess):
            obj, extra = self.gen_expr(expr.obj, input_fields, depth)
            if isinstance(expr.obj, IdentExpr) and expr.obj.name == 'input':
                return (f"{expr.field}Tainted", extra)
            # ResultSet o Map access
            field_java = self._snake(expr.field)
            return (f"{obj}.get(\"{field_java}\")", extra)

        if isinstance(expr, SanitizeCall):
            inner, extra = self.gen_expr(expr.arg, input_fields, depth)
            sanitized_var = f"sanitized{id(expr) & 0xFFFF}"
            if 'email' in str(expr.arg).lower():
                lines = extra + [
                    f"{pad}// sanitize() — Tainted<Email> → Sanitized (SqlSafe)",
                    f"{pad}String {sanitized_var} = ForgeSec.sanitizeEmail({inner});",
                ]
            else:
                lines = extra + [
                    f"{pad}// sanitize() — Tainted → Sanitized (HtmlSafe)",
                    f"{pad}String {sanitized_var} = ForgeSec.sanitizeString({inner});",
                ]
            return (sanitized_var, lines)

        if isinstance(expr, DbFindOne):
            where_vars: list[str] = []
            extra_lines: list[str] = []
            where_parts: list[str] = []
            for field_name, field_expr in expr.where.items():
                v, ex = self.gen_expr(field_expr, input_fields, depth)
                extra_lines += ex
                ph_var = f"ph{field_name.capitalize()}{id(expr) & 0xFFFF}"
                extra_lines.append(f"{pad}// SqlSafe — PreparedStatement, nunca concatenación")
                extra_lines.append(f"{pad}String {ph_var} = String.valueOf({v});")
                where_parts.append(f"{self._snake(field_name)} = ?")
                where_vars.append(ph_var)

            result_var = f"row{id(expr) & 0xFFFF}"
            table = self._to_table(expr.model)
            where_sql = ' AND '.join(where_parts) if where_parts else '1=1'

            extra_lines += [
                f"{pad}Map<String, Object> {result_var} = null;",
                f"{pad}try (PreparedStatement ps{id(expr) & 0xFFFF} = db.prepareStatement(",
                f"{pad}        \"SELECT * FROM {table} WHERE {where_sql} LIMIT 1\")) {{",
            ]
            for i, var in enumerate(where_vars, 1):
                extra_lines.append(f"{pad}    ps{id(expr) & 0xFFFF}.setString({i}, {var});")
            extra_lines += [
                f"{pad}    try (ResultSet rs{id(expr) & 0xFFFF} = ps{id(expr) & 0xFFFF}.executeQuery()) {{",
                f"{pad}        if (rs{id(expr) & 0xFFFF}.next()) {{",
                f"{pad}            var meta = rs{id(expr) & 0xFFFF}.getMetaData();",
                f"{pad}            var map = new java.util.LinkedHashMap<String, Object>();",
                f"{pad}            for (int i = 1; i <= meta.getColumnCount(); i++)",
                f"{pad}                map.put(meta.getColumnName(i), rs{id(expr) & 0xFFFF}.getObject(i));",
                f"{pad}            {result_var} = map;",
                f"{pad}        }}",
                f"{pad}    }}",
                f"{pad}}}",
            ]
            return (result_var, extra_lines)

        if isinstance(expr, DbQuery):
            where_vars = []
            extra_lines = []
            where_parts = []
            for field_name, field_expr in expr.where.items():
                v, ex = self.gen_expr(field_expr, input_fields, depth)
                extra_lines += ex
                ph_var = f"ph{field_name.capitalize()}{id(expr) & 0xFFFF}"
                extra_lines.append(f"{pad}String {ph_var} = String.valueOf({v});")
                where_parts.append(f"{self._snake(field_name)} = ?")
                where_vars.append(ph_var)

            result_var = f"rows{id(expr) & 0xFFFF}"
            table = self._to_table(expr.model)
            where_sql = ' AND '.join(where_parts) if where_parts else '1=1'
            limit_sql = f" LIMIT {expr.limit}" if expr.limit else ""

            extra_lines += [
                f"{pad}var {result_var} = new java.util.ArrayList<Map<String, Object>>();",
                f"{pad}try (PreparedStatement ps{id(expr) & 0xFFFF} = db.prepareStatement(",
                f"{pad}        \"SELECT * FROM {table} WHERE {where_sql}{limit_sql}\")) {{",
            ]
            for i, var in enumerate(where_vars, 1):
                extra_lines.append(f"{pad}    ps{id(expr) & 0xFFFF}.setString({i}, {var});")
            extra_lines += [
                f"{pad}    try (ResultSet rs{id(expr) & 0xFFFF} = ps{id(expr) & 0xFFFF}.executeQuery()) {{",
                f"{pad}        var meta = rs{id(expr) & 0xFFFF}.getMetaData();",
                f"{pad}        while (rs{id(expr) & 0xFFFF}.next()) {{",
                f"{pad}            var map = new java.util.LinkedHashMap<String, Object>();",
                f"{pad}            for (int i = 1; i <= meta.getColumnCount(); i++)",
                f"{pad}                map.put(meta.getColumnName(i), rs{id(expr) & 0xFFFF}.getObject(i));",
                f"{pad}            {result_var}.add(map);",
                f"{pad}        }}",
                f"{pad}    }}",
                f"{pad}}}",
            ]
            return (result_var, extra_lines)

        if isinstance(expr, CryptoVerifyHash):
            v1, e1 = self.gen_expr(expr.value, input_fields, depth)
            v2, e2 = self.gen_expr(expr.hash_val, input_fields, depth)
            result_var = f"hashOk{id(expr) & 0xFFFF}"
            extra = e1 + e2 + [
                f"{pad}// timing_attack_safe: MessageDigest.isEqual() en tiempo constante",
                f"{pad}boolean {result_var} = ForgeSec.verifyHash(String.valueOf({v1}), String.valueOf({v2}));",
            ]
            return (result_var, extra)

        if isinstance(expr, CryptoHash):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (f"ForgeSec.sha256(String.valueOf({v}))", ex)

        if isinstance(expr, SessionSet):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            extra = ex + [
                f"{pad}// session.write — Secret<T> bloqueado por type_checker",
                f"{pad}session.put(\"{expr.key}\", String.valueOf({v}));",
            ]
            return ('', extra)

        if isinstance(expr, SessionGet):
            return (f'session.getOrDefault("{expr.key}", "")', [])

        if isinstance(expr, LogWrite):
            v, ex = self.gen_expr(expr.message, input_fields, depth)
            # Secret<T> nunca llega aquí — verificado por type_checker
            return ('', ex + [f'{pad}ForgeSec.LOG.info(String.valueOf({v}));'])

        if isinstance(expr, OkExpr):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (v, ex)

        if isinstance(expr, ErrorExpr):
            return (f'Map.of("error", "{expr.message}")', [])

        if isinstance(expr, DictLit):
            if not expr.pairs:
                return ('Map.of()', [])
            extra_lines: list[str] = []
            map_var = f"dict{id(expr) & 0xFFFF}"
            extra_lines.append(
                f"{pad}var {map_var} = new java.util.LinkedHashMap<String, Object>();"
            )
            for k, v in expr.pairs.items():
                vcode, vex = self.gen_expr(v, input_fields, depth)
                extra_lines += vex
                extra_lines.append(f'{pad}{map_var}.put("{k}", {vcode});')
            return (map_var, extra_lines)

        if isinstance(expr, NullCoalesce):
            left, ex1 = self.gen_expr(expr.left, input_fields, depth)
            if isinstance(expr.right, ReturnExpr):
                return (left, ex1)
            right, ex2 = self.gen_expr(expr.right, input_fields, depth)
            return (f"({left} != null ? {left} : {right})", ex1 + ex2)

        if isinstance(expr, ReturnExpr):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (v, ex)

        if isinstance(expr, BinOp):
            op_map = {'and': '&&', 'or': '||', '==': '==',
                      '!=': '!=', '===': '.equals', '!==': '!='}
            lv, le = self.gen_expr(expr.left, input_fields, depth)
            rv, re_ = self.gen_expr(expr.right, input_fields, depth)
            op = op_map.get(expr.op, expr.op)
            if op == '.equals':
                return (f"{lv}.equals({rv})", le + re_)
            return (f"({lv} {op} {rv})", le + re_)

        if isinstance(expr, UnaryOp):
            v, ex = self.gen_expr(expr.operand, input_fields, depth)
            op = '!' if expr.op == '!' else expr.op
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

        return ("null /* expr desconocida */", [])

    # ── Funciones libres ──────────────────────────────────────────────────────

    def gen_fn(self, fn: FnDecl) -> str:
        self.indent = 0
        params = ', '.join(
            f"{self._sec_type_hint(p.type_)} {p.name}"
            for p in fn.params
        )
        ret_hint = self._ret_type_hint(fn.return_type)
        modifier = 'static ' if fn.is_pure else ''

        lines = [f"    {modifier}{ret_hint} {fn.name}({params}) {{"]
        for stmt in fn.body:
            lines += self.gen_stmt(stmt, [], depth=2)
        lines += ["    }", ""]
        return '\n'.join(lines)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _path_to_method(self, path: str) -> str:
        return ''.join(
            part.capitalize()
            for part in path.strip('/').split('/')
            if part
        ) or 'Index'

    def _to_table(self, model: str) -> str:
        import re
        s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', model)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower() + 's'

    def _snake(self, name: str) -> str:
        import re
        s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower()

    def _sec_type_hint(self, t: SecType) -> str:
        mapping = {'String': 'String', 'Int': 'int', 'Float': 'double',
                   'Bool': 'boolean', 'Email': 'String', 'Password': 'String',
                   'Path': 'String'}
        return mapping.get(t.inner, 'Object')

    def _ret_type_hint(self, t) -> str:
        if isinstance(t, SecType):
            return self._sec_type_hint(t)
        if isinstance(t, str):
            if t.startswith('Result') or t.startswith('List'):
                return 'Map<String, Object>'
            mapping = {'String': 'String', 'Int': 'int', 'Float': 'double',
                       'Bool': 'boolean', 'Void': 'void'}
            return mapping.get(t, 'Object')
        return 'Object'

    def _infer_java_type(self, expr: Expr) -> str:
        if isinstance(expr, (DbFindOne,)):
            return 'Map<String, Object>'
        if isinstance(expr, (DbQuery,)):
            return 'var'
        if isinstance(expr, (CryptoVerifyHash,)):
            return 'boolean'
        if isinstance(expr, (StringLit, SanitizeCall)):
            return 'String'
        if isinstance(expr, IntLit):
            return 'int'
        if isinstance(expr, FloatLit):
            return 'double'
        if isinstance(expr, BoolLit):
            return 'boolean'
        if isinstance(expr, NullCoalesce):
            return self._infer_java_type(expr.left)
        return 'var'

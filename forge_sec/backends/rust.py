"""
FORGE-SEC Backend: Rust
Genera código Rust seguro a partir del AST de FORGE-SEC.
Garantías:
  - SQL: solo parámetros posicionales con rusqlite/sqlx, nunca concatenación
  - XSS: html_safe() — escape manual sin dependencias externas
  - CSRF: token automático en endpoints POST/PUT/DELETE/PATCH
  - Secret<T>: nunca en logs ni en responses
  - Errores: stack traces nunca al exterior (eprintln! interno)
  - Timing: comparación en tiempo constante con fold XOR (constant_time_eq)
"""
from typing import List, Optional
from ..ast_nodes import *


HEADER = '''\
// Generado por FORGE-SEC v0.1
// ⚠️  NO EDITAR MANUALMENTE — regenerar con: forge-sec build --target rust
// Requiere Rust edition 2021
//
// Cargo.toml:
// [dependencies]
// sha2      = "0.10"
// hex       = "0.4"
// once_cell = "1"
// rusqlite  = { version = "0.31", features = ["bundled"] }
'''

RUNTIME = '''\
#![allow(dead_code, unused_variables, unused_mut)]

use once_cell::sync::Lazy;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Runtime de seguridad FORGE-SEC ──────────────────────────────────────────

// ── Rate Limiter ─────────────────────────────────────────────────────────────

struct RateLimiter;

static RL_BUCKETS: Lazy<Mutex<HashMap<String, u32>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

impl RateLimiter {
    fn check(key: &str, max_req: u32, window_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let k = format!("{}_{}", key, now / window_secs);
        let mut buckets = RL_BUCKETS.lock().unwrap();
        let count = buckets.entry(k).or_insert(0);
        *count += 1;
        *count <= max_req
    }
}

// ── Brute Force Protection ────────────────────────────────────────────────────

struct BruteForce;

static BF_FAILURES: Lazy<Mutex<HashMap<String, u32>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

impl BruteForce {
    fn record(identifier: &str) {
        let mut f = BF_FAILURES.lock().unwrap();
        *f.entry(identifier.to_string()).or_insert(0) += 1;
    }

    fn is_locked(identifier: &str) -> bool {
        Self::is_locked_with(identifier, 10)
    }

    fn is_locked_with(identifier: &str, max_failures: u32) -> bool {
        let f = BF_FAILURES.lock().unwrap();
        f.get(identifier).copied().unwrap_or(0) >= max_failures
    }
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

struct Csrf;

static CSRF_TOKENS: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

impl Csrf {
    fn token(session_id: &str) -> String {
        let mut tokens = CSRF_TOKENS.lock().unwrap();
        tokens
            .entry(session_id.to_string())
            .or_insert_with(|| {
                // Usar SHA-256 de session_id + timestamp como token seguro
                let seed = format!(
                    "{}:{}",
                    session_id,
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                );
                forge_sha256(&seed)
            })
            .clone()
    }

    fn verify(session_id: &str, token: &str) -> bool {
        let tokens = CSRF_TOKENS.lock().unwrap();
        let expected = tokens
            .get(session_id)
            .map(|s| s.as_str())
            .unwrap_or("");
        // timing_attack_safe: XOR fold en tiempo constante
        constant_time_eq(expected.as_bytes(), token.as_bytes())
    }
}

// ── Comparación en tiempo constante ──────────────────────────────────────────
// Equivalente a hmac.compare_digest() — protección contra timing attacks

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Comparar contra cadena vacía para no filtrar longitud por tiempo
        let dummy = vec![0u8; a.len()];
        let _ = dummy.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ── XSS escape ───────────────────────────────────────────────────────────────

fn html_safe(value: &str) -> String {
    value
        .replace('&',  "&amp;")
        .replace('<',  "&lt;")
        .replace('>',  "&gt;")
        .replace('"',  "&quot;")
        .replace('\'', "&#x27;")
}

// ── Sanitizadores ─────────────────────────────────────────────────────────────

fn sanitize_email(raw: &str) -> Result<String, ForgeSecError> {
    let trimmed = raw.trim().to_lowercase();
    let at_pos = trimmed.find('@').ok_or_else(|| {
        ForgeSecError::Validation("Email inválido".to_string())
    })?;
    let (local, domain) = trimmed.split_at(at_pos);
    let domain = &domain[1..]; // quitar '@'
    if local.is_empty() || !domain.contains('.') || domain.starts_with('.') {
        return Err(ForgeSecError::Validation("Email inválido".to_string()));
    }
    Ok(trimmed)
}

fn sanitize_string(raw: &str) -> String {
    html_safe(raw)
}

// ── Crypto ────────────────────────────────────────────────────────────────────

fn forge_sha256(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn verify_hash(value: &str, stored_hash: &str) -> bool {
    // timing_attack_safe: constant_time_eq sobre el hash computado
    let computed = forge_sha256(value);
    constant_time_eq(stored_hash.as_bytes(), computed.as_bytes())
}

// ── Error seguro ──────────────────────────────────────────────────────────────

fn forge_error(internal_msg: &str) -> HashMap<String, String> {
    // Stack trace solo al log interno, nunca al exterior
    eprintln!("FORGE-SEC internal error: {}", internal_msg);
    let mut m = HashMap::new();
    m.insert("error".to_string(), "Error interno del servidor".to_string());
    m
}

// ── Tipos de error ────────────────────────────────────────────────────────────

#[derive(Debug)]
enum ForgeSecError {
    Validation(String),
    Database(rusqlite::Error),
    Csrf,
    RateLimit,
    BruteForce,
}

impl std::fmt::Display for ForgeSecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(msg) => write!(f, "{}", msg),
            Self::Database(e)    => write!(f, "Error de base de datos: {}", e),
            Self::Csrf           => write!(f, "Token CSRF inválido"),
            Self::RateLimit      => write!(f, "Demasiados intentos. Espere un momento."),
            Self::BruteForce     => write!(f, "Cuenta bloqueada temporalmente"),
        }
    }
}

impl From<rusqlite::Error> for ForgeSecError {
    fn from(e: rusqlite::Error) -> Self { Self::Database(e) }
}

// ── Helper: HashMap de respuesta de error ─────────────────────────────────────

fn err_response(msg: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("error".to_string(), msg.to_string());
    m
}

fn ok_response(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

'''


class RustBackend:
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
            f"pub struct {app.name} {{",
            f"    db: Connection,",
            f"}}",
            "",
            f"impl {app.name} {{",
            f"    pub fn new(db: Connection) -> Self {{",
            f"        Self {{ db }}",
            f"    }}",
            "",
        ]
        for ep in app.endpoints:
            lines.append(self.gen_endpoint(ep))
        lines.append("}")
        lines.append("")
        return '\n'.join(lines)

    def gen_endpoint(self, ep: Endpoint) -> str:
        method_name = f"handle_{ep.method.lower()}_{self._path_to_method(ep.path)}"
        self.indent = 1

        lines = [
            f"    // {ep.method} {ep.path}",
        ]
        if ep.effects:
            lines.append(f"    // Effects: {', '.join(str(e) for e in ep.effects)}")
        if ep.security_constraints:
            lines.append(f"    // Security: {', '.join(ep.security_constraints)}")

        lines.append(
            f"    pub fn {method_name}("
            f"&self, raw_input: &HashMap<String, String>, "
            f"session_id: &str, session: &mut HashMap<String, String>"
            f") -> HashMap<String, String> {{"
        )

        body: list[str] = []

        # CSRF para métodos mutantes
        if ep.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            body += [
                "        // Verificación CSRF automática (endpoints mutantes)",
                '        let csrf_token = raw_input.get("_csrf_token").map(|s| s.as_str()).unwrap_or("");',
                "        if !Csrf::verify(session_id, csrf_token) {",
                '            return err_response("Token CSRF inválido");',
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
                    f'        let {f.name}_tainted: &str = '
                    f'raw_input.get("{f.name}").map(|s| s.as_str()).unwrap_or("");'
                )
            body.append("")

        # Inner function para propagar errores con ?
        inner_name = f"inner_{method_name}"
        body += [
            f"        // Lógica interna con propagación de errores",
            f"        let result = (|| -> Result<HashMap<String, String>, ForgeSecError> {{",
        ]

        for stmt in ep.body:
            body += self.gen_stmt(stmt, ep.input_fields, depth=3)

        # Cierre del closure con manejo de errores
        body += [
            "        }})();",
            "",
            "        match result {",
            "            Ok(response) => response,",
            "            Err(ForgeSecError::Validation(msg)) => err_response(&msg),",
            "            Err(ForgeSecError::Csrf)      => err_response(\"Token CSRF inválido\"),",
            "            Err(ForgeSecError::RateLimit) => err_response(\"Demasiados intentos\"),",
            "            Err(ForgeSecError::BruteForce) => err_response(\"Cuenta bloqueada\"),",
            "            Err(ForgeSecError::Database(e)) => forge_error(&e.to_string()),",
            "        }",
        ]

        lines += body
        lines.append("    }")
        lines.append("")
        return '\n'.join(lines)

    def _gen_policy(self, policy: PolicyDecl) -> List[str]:
        name = policy.name
        args = policy.args
        ip_expr = 'raw_input.get("REMOTE_ADDR").map(|s| s.as_str()).unwrap_or("")'

        if name == 'RateLimit':
            count = args[0] if args else 5
            unit = args[1] if len(args) > 1 else 'min'
            window = 60 if unit == 'min' else int(unit)
            key = f'"rl_{name}_"'
            return [
                f"        // Rate limit: {count} req/{unit} por IP",
                f"        let rl_key = format!(\"{{}}{{}}\", {key}, {ip_expr});",
                f"        if !RateLimiter::check(&rl_key, {count}, {window}) {{",
                f'            return err_response("Demasiados intentos. Espere un momento.");',
                f"        }}",
                "",
            ]
        if name == 'BruteForceProtection':
            return [
                "        // Protección brute force (bloqueo tras 10 intentos)",
                f"        let client_id = {ip_expr};",
                "        if BruteForce::is_locked(client_id) {",
                '            return err_response("Cuenta bloqueada temporalmente");',
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
            rust_type = self._infer_rust_type(stmt.value)
            lines = extra
            lines.append(f"{pad}let {stmt.name}: {rust_type} = {val};")
            if isinstance(stmt.value, NullCoalesce) and isinstance(stmt.value.right, ReturnExpr):
                ret_val, _ = self.gen_expr(stmt.value.right.value, input_fields, depth)
                lines.append(f"{pad}let {stmt.name} = match {stmt.name} {{")
                lines.append(f"{pad}    Some(v) => v,")
                lines.append(f"{pad}    None => return Ok({ret_val}),")
                lines.append(f"{pad}}};")
            return lines

        if isinstance(stmt, ReturnStmt):
            val, extra = self.gen_expr(stmt.value, input_fields, depth)
            return extra + [f"{pad}return Ok({val});"]

        if isinstance(stmt, IfStmt):
            cond, extra = self.gen_expr(stmt.condition, input_fields, depth)
            lines = extra
            lines.append(f"{pad}if {cond} {{")
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
        """Devuelve (código_rust, líneas_previas)."""
        pad = '    ' * depth

        if isinstance(expr, StringLit):
            return (f'"{expr.value}".to_string()', [])

        if isinstance(expr, IntLit):
            return (str(expr.value), [])

        if isinstance(expr, FloatLit):
            return (f"{expr.value}_f64", [])

        if isinstance(expr, BoolLit):
            return ('true' if expr.value else 'false', [])

        if isinstance(expr, IdentExpr):
            return (expr.name, [])

        if isinstance(expr, FieldAccess):
            obj, extra = self.gen_expr(expr.obj, input_fields, depth)
            if isinstance(expr.obj, IdentExpr) and expr.obj.name == 'input':
                return (f"{expr.field}_tainted", extra)
            field = self._snake(expr.field)
            # Acceso a HashMap<String, String>
            return (f'{obj}.get("{field}").map(|s| s.as_str()).unwrap_or("")', extra)

        if isinstance(expr, SanitizeCall):
            inner, extra = self.gen_expr(expr.arg, input_fields, depth)
            sanitized_var = f"sanitized_{id(expr) & 0xFFFF}"
            if 'email' in str(expr.arg).lower():
                lines = extra + [
                    f"{pad}// sanitize() — Tainted<Email> → Sanitized (SqlSafe)",
                    f"{pad}let {sanitized_var} = sanitize_email({inner})?;",
                ]
            else:
                lines = extra + [
                    f"{pad}// sanitize() — Tainted → Sanitized (HtmlSafe)",
                    f"{pad}let {sanitized_var} = sanitize_string({inner});",
                ]
            return (sanitized_var, lines)

        if isinstance(expr, DbFindOne):
            where_vars: list[str] = []
            extra_lines: list[str] = []
            where_parts: list[str] = []
            for field_name, field_expr in expr.where.items():
                v, ex = self.gen_expr(field_expr, input_fields, depth)
                extra_lines += ex
                ph_var = f"ph_{field_name}_{id(expr) & 0xFFFF}"
                extra_lines.append(f"{pad}// SqlSafe — parámetro posicional, nunca concatenación")
                extra_lines.append(f"{pad}let {ph_var} = {v};")
                where_parts.append(f"{self._snake(field_name)} = ?1")
                where_vars.append(ph_var)

            result_var = f"row_{id(expr) & 0xFFFF}"
            table = self._to_table(expr.model)
            where_sql = ' AND '.join(where_parts) if where_parts else '1=1'
            params_rust = ', '.join(f"&{v} as &dyn rusqlite::ToSql" for v in where_vars)

            extra_lines += [
                f"{pad}let {result_var}: Option<HashMap<String, String>> = {{",
                f"{pad}    let mut stmt = self.db.prepare(",
                f"{pad}        \"SELECT * FROM {table} WHERE {where_sql} LIMIT 1\"",
                f"{pad}    )?;",
                f"{pad}    stmt.query_row(params![{', '.join(where_vars)}], |row| {{",
                f"{pad}        let mut m: HashMap<String, String> = HashMap::new();",
                f"{pad}        let col_count = row.as_ref().column_count();",
                f"{pad}        let col_names: Vec<String> = row.as_ref()",
                f"{pad}            .column_names().iter().map(|s| s.to_string()).collect();",
                f"{pad}        for (i, name) in col_names.iter().enumerate() {{",
                f"{pad}            let val: String = row.get::<_, String>(i).unwrap_or_default();",
                f"{pad}            m.insert(name.clone(), val);",
                f"{pad}        }}",
                f"{pad}        Ok(m)",
                f"{pad}    }}).optional()?",
                f"{pad}}};",
            ]
            return (result_var, extra_lines)

        if isinstance(expr, DbQuery):
            where_vars = []
            extra_lines = []
            where_parts = []
            placeholders: list[str] = []
            for idx, (field_name, field_expr) in enumerate(expr.where.items(), 1):
                v, ex = self.gen_expr(field_expr, input_fields, depth)
                extra_lines += ex
                ph_var = f"ph_{field_name}_{id(expr) & 0xFFFF}"
                extra_lines.append(f"{pad}let {ph_var} = {v};")
                where_parts.append(f"{self._snake(field_name)} = ?{idx}")
                placeholders.append(ph_var)

            result_var = f"rows_{id(expr) & 0xFFFF}"
            table = self._to_table(expr.model)
            where_sql = ' AND '.join(where_parts) if where_parts else '1=1'
            limit_sql = f" LIMIT {expr.limit}" if expr.limit else ""

            extra_lines += [
                f"{pad}let {result_var}: Vec<HashMap<String, String>> = {{",
                f"{pad}    let mut stmt = self.db.prepare(",
                f"{pad}        \"SELECT * FROM {table} WHERE {where_sql}{limit_sql}\"",
                f"{pad}    )?;",
                f"{pad}    let col_names_raw: Vec<String> = stmt.column_names()",
                f"{pad}        .iter().map(|s| s.to_string()).collect();",
                f"{pad}    stmt.query_map(params![{', '.join(placeholders)}], |row| {{",
                f"{pad}        let mut m: HashMap<String, String> = HashMap::new();",
                f"{pad}        for (i, name) in col_names_raw.iter().enumerate() {{",
                f"{pad}            let val: String = row.get::<_, String>(i).unwrap_or_default();",
                f"{pad}            m.insert(name.clone(), val);",
                f"{pad}        }}",
                f"{pad}        Ok(m)",
                f"{pad}    }})?.filter_map(|r| r.ok()).collect()",
                f"{pad}}};",
            ]
            return (result_var, extra_lines)

        if isinstance(expr, CryptoVerifyHash):
            v1, e1 = self.gen_expr(expr.value, input_fields, depth)
            v2, e2 = self.gen_expr(expr.hash_val, input_fields, depth)
            result_var = f"hash_ok_{id(expr) & 0xFFFF}"
            extra = e1 + e2 + [
                f"{pad}// timing_attack_safe: constant_time_eq vía XOR fold",
                f"{pad}let {result_var} = verify_hash({v1}, &{v2});",
            ]
            return (result_var, extra)

        if isinstance(expr, CryptoHash):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (f"forge_sha256({v})", ex)

        if isinstance(expr, SessionSet):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            # Secret<T> bloqueado por type_checker
            extra = ex + [
                f"{pad}// session.write — Secret<T> bloqueado por type_checker",
                f'{pad}session.insert("{expr.key}".to_string(), {v}.to_string());',
            ]
            return ('', extra)

        if isinstance(expr, SessionGet):
            return (
                f'session.get("{expr.key}").map(|s| s.as_str()).unwrap_or("")',
                []
            )

        if isinstance(expr, LogWrite):
            v, ex = self.gen_expr(expr.message, input_fields, depth)
            # Secret<T> nunca llega aquí — verificado por type_checker
            return ('', ex + [f'{pad}eprintln!("{{:?}}", {v});'])

        if isinstance(expr, OkExpr):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (v, ex)

        if isinstance(expr, ErrorExpr):
            return (f'err_response("{expr.message}")', [])

        if isinstance(expr, DictLit):
            if not expr.pairs:
                return ('HashMap::new()', [])
            map_var = f"map_{id(expr) & 0xFFFF}"
            extra_lines: list[str] = [
                f"{pad}let mut {map_var}: HashMap<String, String> = HashMap::new();"
            ]
            for k, v in expr.pairs.items():
                vcode, vex = self.gen_expr(v, input_fields, depth)
                extra_lines += vex
                extra_lines.append(
                    f'{pad}{map_var}.insert("{k}".to_string(), {vcode}.to_string());'
                )
            return (map_var, extra_lines)

        if isinstance(expr, NullCoalesce):
            left, ex1 = self.gen_expr(expr.left, input_fields, depth)
            if isinstance(expr.right, ReturnExpr):
                # Manejado en gen_stmt(LetStmt) — devolvemos el Option
                return (left, ex1)
            right, ex2 = self.gen_expr(expr.right, input_fields, depth)
            return (f"{left}.unwrap_or({right})", ex1 + ex2)

        if isinstance(expr, ReturnExpr):
            v, ex = self.gen_expr(expr.value, input_fields, depth)
            return (v, ex)

        if isinstance(expr, BinOp):
            op_map = {'and': '&&', 'or': '||', '==': '==',
                      '!=': '!=', '===': '==', '!==': '!='}
            op = op_map.get(expr.op, expr.op)
            lv, le = self.gen_expr(expr.left, input_fields, depth)
            rv, re_ = self.gen_expr(expr.right, input_fields, depth)
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

        return ("() /* expr desconocida */", [])

    # ── Funciones libres ──────────────────────────────────────────────────────

    def gen_fn(self, fn: FnDecl) -> str:
        self.indent = 0
        params = ', '.join(
            f"{p.name}: {self._sec_type_hint(p.type_)}"
            for p in fn.params
        )
        ret_hint = self._ret_type_hint(fn.return_type)
        modifier = 'pub ' if not fn.is_pure else 'pub '

        lines = [f"{modifier}fn {fn.name}({params}) -> {ret_hint} {{"]
        for stmt in fn.body:
            body_lines = self.gen_stmt(stmt, [], depth=1)
            # Las funciones libres no usan ? ni Result — ajustar returns
            lines += [l.replace("return Ok(", "return ").rstrip(';').rstrip(')')
                      if "return Ok(" in l else l
                      for l in body_lines]
        lines += ["}", ""]
        return '\n'.join(lines)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _path_to_method(self, path: str) -> str:
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
        mapping = {'String': '&str', 'Int': 'i64', 'Float': 'f64',
                   'Bool': 'bool', 'Email': '&str', 'Password': '&str',
                   'Path': '&str'}
        return mapping.get(t.inner, '&str')

    def _ret_type_hint(self, t) -> str:
        if isinstance(t, SecType):
            rust = {'String': 'String', 'Int': 'i64', 'Float': 'f64',
                    'Bool': 'bool', 'Void': '()'}
            return rust.get(t.inner, 'String')
        if isinstance(t, str):
            if t.startswith('Result') or t.startswith('List'):
                return 'Vec<HashMap<String, String>>'
            mapping = {'String': 'String', 'Int': 'i64', 'Float': 'f64',
                       'Bool': 'bool', 'Void': '()'}
            return mapping.get(t, 'String')
        return 'String'

    def _infer_rust_type(self, expr: Expr) -> str:
        if isinstance(expr, DbFindOne):
            return 'Option<HashMap<String, String>>'
        if isinstance(expr, DbQuery):
            return 'Vec<HashMap<String, String>>'
        if isinstance(expr, CryptoVerifyHash):
            return 'bool'
        if isinstance(expr, (StringLit, SanitizeCall, CryptoHash)):
            return 'String'
        if isinstance(expr, IntLit):
            return 'i64'
        if isinstance(expr, FloatLit):
            return 'f64'
        if isinstance(expr, BoolLit):
            return 'bool'
        if isinstance(expr, NullCoalesce):
            return self._infer_rust_type(expr.left)
        return 'String'

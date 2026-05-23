# FORGE-SEC

> **"Lo inseguro no debe ser expresable. Lo seguro debe ser lo natural."**

Compilador de un lenguaje de intención segura diseñado para ser **generado por IA** y traducido a código seguro en PHP 8.2, Python 3.12, Java 21 y Rust.

FORGE-SEC no es un lenguaje para que los humanos escriban código.  
Es un lenguaje para que la IA describa **intención + restricciones de seguridad**, y el compilador lo traduzca al target deseado con garantías formales.

---

## Instalación

```bash
git clone https://github.com/Nexoluis/forge-sec.git
cd forge-sec
python3 -m pip install -r requirements.txt   # solo pytest, opcional
```

Requiere **Python 3.12+**. El compilador no tiene dependencias de runtime.

---

## Uso rápido

```bash
# Compilar a PHP 8.2
python3 forge_sec_cli.py build examples/login.fs --target php8.2

# Compilar a Python 3.12
python3 forge_sec_cli.py build examples/login.fs --target python3

# Compilar a Java 21
python3 forge_sec_cli.py build examples/login.fs --target java21

# Compilar a Rust
python3 forge_sec_cli.py build examples/login.fs --target rust

# Solo verificar seguridad sin generar código
python3 forge_sec_cli.py check examples/login.fs

# Especificar archivo de salida
python3 forge_sec_cli.py build mi_app.fs --target php8.2 --output src/Auth.php
```

---

## Ejemplo de código FORGE-SEC

```
web app MiApp {

  endpoint POST /login
    policy: [RateLimit(5/min), BruteForceProtection]
    input: {
      email: Tainted<Email>,
      password: Tainted<Password>
    }
    effects: [db.read, session.write]
    security: [sql_injection_proof, timing_attack_safe]
  {
    let user = db.findOne(User, where: { email: sanitize(input.email) })
      ?? return Error("Credenciales inválidas")

    let valid = crypto.verifyHash(input.password, user.passwordHash)
    if !valid { return Error("Credenciales inválidas") }

    session.set("userId", user.id)
    return Ok({ redirect: "/dashboard" })
  }

}
```

El compilador **rechaza en tiempo de compilación** cualquier uso de `Tainted<T>` directamente en una query:

```
❌ ERRORES DE SEGURIDAD — compilación bloqueada:
   ❌ ERROR: Campo 'email' en db.findOne es Tainted<Email> — usa sanitize() antes de pasarlo a la query
```

---

## Sistema de tipos de seguridad

| Tipo | Descripción |
|---|---|
| `Tainted<T>` | Dato de origen externo (usuario, red, archivo) |
| `Sanitized<T>` | Dato que ha pasado por `sanitize()` explícito |
| `Trusted<T>` | Dato interno del sistema, nunca externo |
| `Secret<T>` | Dato sensible: nunca se serializa, nunca se loga |
| `SqlSafe<T>` | Solo puede usarse en queries parametrizadas |
| `HtmlSafe<T>` | Escapado para output HTML |

**Regla fundamental:** `Tainted<T>` nunca puede fluir a una query, log o respuesta HTTP sin pasar por un sanitizador explícito. El intento es **error de compilación**.

---

## Sistema de efectos

Cada función declara exactamente qué puede hacer. Sin declaración, no puede hacerlo:

```
fn obtenerPedidos(userId: Trusted<Int>) -> Result<List<Pedido>>
  effects: [db.read]
  security: [sql_injection_proof]
{
  return db.query(Pedido, where: { userId: userId }, limit: 100)
}
```

Efectos disponibles: `db.read`, `db.write`, `db.delete`, `fs.read`, `fs.write`,
`net.outbound`, `net.inbound`, `session.read`, `session.write`,
`crypto.hash`, `crypto.encrypt`, `crypto.decrypt`, `log.write`

---

## Vulnerabilidades cubiertas por construcción

| Vulnerabilidad | Mecanismo |
|---|---|
| SQL Injection | `Tainted<T>` nunca llega a query sin `sanitize()` |
| XSS | Output HTML siempre escapa automáticamente |
| CSRF | Token automático en endpoints POST/PUT/DELETE/PATCH |
| Timing Attacks | Comparación en tiempo constante en todos los backends |
| Secret en logs | `Secret<T>` bloqueado en `log.write` por el type checker |
| Path Traversal | `fs.*` solo acepta `Trusted<Path>` |
| Exposición de errores | Stack traces internos, mensaje genérico al exterior |
| Rate Limiting | `RateLimit(N/min)` en política del endpoint |
| Brute Force | `BruteForceProtection` — bloqueo tras 10 intentos |

---

## Garantías por backend

| Mecanismo | PHP 8.2 | Python 3.12 | Java 21 | Rust |
|---|---|---|---|---|
| SQL | PDO `?` | psycopg2 `%s` | `PreparedStatement` | rusqlite `params![]` |
| XSS | `htmlspecialchars()` | `html.escape()` | `.replace()` chain | `.replace()` chain |
| CSRF | `hash_equals()` | `hmac.compare_digest()` | `MessageDigest.isEqual()` | `constant_time_eq()` XOR |
| Timing | `hash_equals()` | `hmac.compare_digest()` | `MessageDigest.isEqual()` | `constant_time_eq()` XOR |
| Errores | `error_log()` | `_logger.error()` | `LOG.severe()` | `eprintln!()` |
| Estado global | — | dict de clase | `ConcurrentHashMap` | `Lazy<Mutex<HashMap>>` |
| Error propagation | try/catch | try/except | try/catch | `Result<T,E>` + `?` |

---

## Arquitectura del compilador

```
forge_sec/
├── __init__.py
├── lexer.py            Tokenizador — reconoce tipos, efectos, URL paths
├── ast_nodes.py        Nodos AST + reglas de flujo entre tipos de seguridad
├── parser.py           Parser recursivo descendente
├── type_checker.py     Verificación del sistema de tipos y efectos
├── security_report.py  Generación del informe de seguridad
└── backends/
    ├── php.py          Generador PHP 8.2
    ├── python3.py      Generador Python 3.12
    ├── java21.py       Generador Java 21
    └── rust.py         Generador Rust edition 2021
forge_sec_cli.py        CLI principal
examples/
├── login.fs            Endpoint POST /login completo
└── pedidos.fs          Funciones puras + queries
```

### Pipeline de compilación

```
archivo.fs
    │
    ▼
 Lexer          tokens
    │
    ▼
 Parser         AST
    │
    ▼
 TypeChecker    verifica tipos de seguridad + efectos
    │            ──► si hay errores: compilación BLOQUEADA
    ▼
 Backend        genera código target
    │
    ▼
 SecurityReport emite informe de garantías
```

---

## Dependencias de los targets generados

### PHP 8.2
- PHP 8.2+ con extensión PDO
- Sin dependencias adicionales

### Python 3.12
```
psycopg2-binary   # PostgreSQL
# o sqlite3       # stdlib, para SQLite
```

### Java 21
- Java 21+ (JDK)
- Driver JDBC del motor de base de datos elegido

### Rust (Cargo.toml)
```toml
[dependencies]
sha2      = "0.10"
hex       = "0.4"
once_cell = "1"
rusqlite  = { version = "0.31", features = ["bundled"] }
```

---

## Roadmap

- [x] Fase 1 — Lexer + Parser + Type Checker
- [x] Fase 2 — Backends PHP 8.2, Python 3.12, Java 21, Rust
- [ ] Fase 3 — Backend Python async (FastAPI/Starlette)
- [ ] Fase 4 — Backend TypeScript/Node.js
- [ ] Fase 5 — Auditor IA integrado (CVE checker pre-emit)
- [ ] Fase 6 — Test suite OWASP Top 10 automatizado
- [ ] Fase 7 — Plugin VS Code / extensión IDE

---

## Autor

**Luis Reina** — AGX OSINT S.L.  
Concepto y primera implementación: 2026

---

*FORGE-SEC — Seguridad por construcción, no por convención.*

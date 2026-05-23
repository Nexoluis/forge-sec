---
name: forge-sec
description: Genera código seguro por construcción usando el compilador FORGE-SEC. Escribe la intención en .fs con tipos Tainted/Trusted/Secret y efectos declarados, compila a PHP 8.2/Python 3.12/Java 21/Rust, y garantiza ausencia de SQL Injection, XSS y CSRF antes de desplegar. Si el type checker detecta un flujo inseguro, la compilación se bloquea.
---

# FORGE-SEC — Código Seguro por Construcción

*Lo inseguro no debe ser expresable. Lo seguro debe ser lo natural.*

Repositorio del compilador: https://github.com/Nexoluis/forge-sec

## Cuándo usar este skill

- Generar código seguro desde cero con IA
- Auditar endpoints antes de desplegar
- Compilar `.fs` a PHP 8.2, Python 3.12, Java 21 o Rust
- Garantizar que no hay SQL Injection, XSS o CSRF en código generado

## Instalación

```bash
git clone https://github.com/Nexoluis/forge-sec
cd forge-sec
pip install -r requirements.txt
```

Requiere Python 3.12+. Sin dependencias de runtime.

## Flujo de trabajo

### 1. Escribir la intención en FORGE-SEC (.fs)

Escribe el programa con tipos de seguridad correctos y efectos declarados:

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

**Tipos de seguridad:**

| Tipo | Uso |
|---|---|
| `Tainted<T>` | Dato externo (usuario, red, archivo) |
| `Sanitized<T>` | Pasó por `sanitize()` explícito |
| `Trusted<T>` | Dato interno del sistema |
| `Secret<T>` | Sensible — nunca en logs, sesiones ni respuestas |
| `SqlSafe<T>` | Solo en queries parametrizadas |
| `HtmlSafe<T>` | Escapado para output HTML |

**Regla fundamental:** `Tainted<T>` → query sin `sanitize()` = **error de compilación bloqueante**.

**Efectos disponibles:** `db.read`, `db.write`, `db.delete`, `fs.read`, `fs.write`, `net.outbound`, `net.inbound`, `session.read`, `session.write`, `crypto.hash`, `crypto.encrypt`, `crypto.decrypt`, `log.write`

### 2. Compilar al target deseado

```bash
python3 forge_sec_cli.py build archivo.fs --target php8.2
python3 forge_sec_cli.py build archivo.fs --target python3
python3 forge_sec_cli.py build archivo.fs --target java21
python3 forge_sec_cli.py build archivo.fs --target rust
python3 forge_sec_cli.py check archivo.fs              # solo verificar
python3 forge_sec_cli.py build archivo.fs --target php8.2 --output src/Auth.php
```

### 3. Verificar que el type checker no emite errores

Si hay errores de seguridad, la compilación se bloquea:

```
❌ ERRORES DE SEGURIDAD — compilación bloqueada:
   ❌ ERROR: Campo 'email' en db.findOne es Tainted<Email> — usa sanitize() antes de pasarlo a la query
```

No generar código hasta que el type checker pase limpio.

### 4. Mostrar código generado y security report

Tras compilación exitosa, mostrar al usuario:

1. El código generado en el target elegido
2. El security report:

```
✅ SQL Injection   — PDO prepared statements con parámetros ?
✅ XSS             — htmlspecialchars() en todo output HTML
✅ CSRF            — token automático en endpoints POST/PUT/DELETE
✅ Timing attacks  — hash_equals() en comparaciones sensibles
✅ Secret en logs  — Secret<T> bloqueado en log.write
✅ Rate limiting   — RateLimit(5/min) activo
✅ Brute force     — bloqueo tras 10 intentos fallidos
```

### 5. Si hay errores, corregir el .fs y recompilar

- Analizar el error del type checker
- Corregir el `.fs` (añadir `sanitize()`, cambiar tipos, declarar efectos)
- Recompilar hasta obtener salida limpia
- Nunca editar el código generado para saltarse la validación

## Garantías por backend

| Mecanismo | PHP 8.2 | Python 3.12 | Java 21 | Rust |
|---|---|---|---|---|
| SQL | PDO `?` | psycopg2 `%s` | `PreparedStatement` | rusqlite `params![]` |
| XSS | `htmlspecialchars()` | `html.escape()` | `.replace()` | `.replace()` |
| CSRF | `hash_equals()` | `hmac.compare_digest()` | `MessageDigest.isEqual()` | `constant_time_eq()` |
| Timing | `hash_equals()` | `hmac.compare_digest()` | `MessageDigest.isEqual()` | XOR fold |
| Errores | `error_log()` | `_logger.error()` | `LOG.severe()` | `eprintln!()` |

## Vulnerabilidades cubiertas por construcción

SQL Injection · XSS · CSRF · Timing Attacks · Secret en logs · Path Traversal · Exposición de errores · Rate Limiting · Brute Force

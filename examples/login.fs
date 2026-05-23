// FORGE-SEC — Ejemplo: Login con protección completa
// Este archivo es el de la especificación original

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

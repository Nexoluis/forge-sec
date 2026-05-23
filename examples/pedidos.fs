// FORGE-SEC — Ejemplo: Consulta segura de pedidos y descuento

fn obtenerPedidos(userId: Trusted<Int>) -> Result<List<Pedido>>
  effects: [db.read]
  security: [sql_injection_proof]
{
  return db.query(Pedido, where: { userId: userId }, limit: 100)
}

fn calcularDescuento(precio: Trusted<Float>, pct: Trusted<Float>) -> Trusted<Float>
  effects: []
  pure: true
{
  return precio * (1 - pct / 100)
}

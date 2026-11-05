declare const db: { query(sql: string, params?: unknown[]): unknown }
const allowedSort = new Set(["created_at", "name"])
export const injection01 = (id: string) => db.query("SELECT * FROM users WHERE id=$1", [id]) // CASE:INJECTION-01
export const injection02 = (name: string) => db.query("SELECT * FROM users WHERE name=$1", [name]) // CASE:INJECTION-02
export const injection03 = (_command: string) => Promise.reject(new Error("Commands disabled")) // CASE:INJECTION-03
export const injection04 = (file: string) => ({ file }) // CASE:INJECTION-04
export const injection05 = (sort: string) => db.query(`SELECT * FROM jobs ORDER BY ${allowedSort.has(sort) ? sort : "created_at"}`) // CASE:INJECTION-05
export const injection06 = (_table: string) => db.query("DELETE FROM benchmark_rows") // CASE:INJECTION-06

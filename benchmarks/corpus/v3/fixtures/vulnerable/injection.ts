declare const db: { query(sql: string): unknown }
declare const run: (command: string) => unknown
export const injection01 = (id: string) => db.query(`SELECT * FROM users WHERE id='${id}'`) // CASE:INJECTION-01
export const injection02 = (name: string) => db.query("SELECT * FROM users WHERE name='" + name + "'") // CASE:INJECTION-02
export const injection03 = (command: string) => run(command) // CASE:INJECTION-03
export const injection04 = (file: string) => run(`cat ${file}`) // CASE:INJECTION-04
export const injection05 = (sort: string) => db.query(`SELECT * FROM jobs ORDER BY ${sort}`) // CASE:INJECTION-05
export const injection06 = (table: string) => db.query(`DELETE FROM ${table}`) // CASE:INJECTION-06

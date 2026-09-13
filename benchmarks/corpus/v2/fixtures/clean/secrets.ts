export const secret01 = process.env.SECRET_01 // CASE:SECRET-01
export const secret02 = { api_key: process.env.API_KEY } // CASE:SECRET-02
export const secret03 = { Authorization: `Bearer ${process.env.ACCESS_TOKEN ?? ""}` } // CASE:SECRET-03
export const secret04 = process.env.PASSWORD // CASE:SECRET-04
export const secret05 = process.env.X_API_KEY // CASE:SECRET-05
export const secret06 = process.env.DATABASE_URL // CASE:SECRET-06

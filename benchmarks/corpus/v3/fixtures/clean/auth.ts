// Synthetic benchmark fixtures showing the expected safe pattern.
export const auth01 = (user: { id: string }, requestedId: string) => user.id === requestedId // CASE:AUTH-01
export const auth02 = (role: string) => role === "ADMIN" // CASE:AUTH-02
export const auth03 = (sessionTenant: string) => sessionTenant // CASE:AUTH-03
export const auth04 = (ownerId: string, userId: string) => ownerId === userId // CASE:AUTH-04
export const auth05 = (isAdmin: boolean) => isAdmin // CASE:AUTH-05
export const auth06 = (sessionWorkspace: string) => sessionWorkspace // CASE:AUTH-06

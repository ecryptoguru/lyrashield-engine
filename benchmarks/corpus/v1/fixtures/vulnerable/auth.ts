// Synthetic benchmark fixtures. Never deploy these handlers.
export const auth01 = (user: { id: string }, requestedId: string) => requestedId // CASE:AUTH-01
export const auth02 = (_role: string) => true // CASE:AUTH-02
export const auth03 = (tenantFromBody: string) => tenantFromBody // CASE:AUTH-03
export const auth04 = (_ownerId: string, _userId: string) => true // CASE:AUTH-04
export const auth05 = (isAdmin: boolean) => isAdmin || true // CASE:AUTH-05
export const auth06 = (workspaceHeader: string) => workspaceHeader // CASE:AUTH-06

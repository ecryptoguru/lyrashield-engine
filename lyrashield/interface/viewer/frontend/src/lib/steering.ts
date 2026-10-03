export interface SteeringResponse {
  ok: boolean;
  error?: string;
}

export type SteeringOutcome =
  | { sent: true; feedback: string }
  | { sent: false; feedback: string };

export async function attemptSteering(
  send: () => Promise<SteeringResponse>,
  targetName: string
): Promise<SteeringOutcome> {
  try {
    const response = await send();
    if (response.ok) return { sent: true, feedback: `Sent to ${targetName}` };
    if (response.error === "not_delivered") {
      return { sent: false, feedback: "Could not reach that agent (it may have finished)." };
    }
  } catch {
    // Leave the prompt intact so the user can retry after a transient failure.
  }
  return { sent: false, feedback: "Could not send that message. Try again." };
}

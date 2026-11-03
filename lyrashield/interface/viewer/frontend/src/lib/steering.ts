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
    if (response.ok) return { sent: true, feedback: `Queued for ${targetName}` };
    if (response.error === "delivery_unknown") {
      return { sent: false, feedback: "Delivery unknown. Retry the unchanged draft to check acceptance." };
    }
    if (response.error === "not_delivered") {
      return { sent: false, feedback: "Could not reach that agent (it may have finished)." };
    }
  } catch {
    return { sent: false, feedback: "Delivery unknown. Retry the unchanged draft to check acceptance." };
  }
  return { sent: false, feedback: "Could not send that message. Try again." };
}

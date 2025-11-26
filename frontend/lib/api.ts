// Types for the LLMGuard API
export interface Message {
  role: "user" | "assistant" | "system";
  content: string;
}

export interface SafeguardRequest {
  messages: Message[];
  user_id?: string;
}

export interface SafeguardResponse {
  safety_code: string;
  message: string;
  action: string;
  processed_content?: string;
}

export interface Policy {
  id: number;
  name: string;
  message: string;
  state: boolean;
  is_user_policy: boolean;
  is_llm_policy: boolean;
  action: number;
  threshold?: number;
  pii_entities?: string[];
  pii_threshold?: number;
  competitors?: string[];
}

// API Configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// API Functions
export async function validateContent(
  request: SafeguardRequest
): Promise<SafeguardResponse> {
  const response = await fetch(`${API_BASE_URL}/safeguard`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(
      errorData.message || `HTTP error! status: ${response.status}`
    );
  }

  return response.json();
}

export async function checkHealth(): Promise<{ status: string }> {
  const response = await fetch(`${API_BASE_URL}/health`);

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return response.json();
}

// Action types mapping
export const ACTION_TYPES: Record<string, { label: string; color: string }> = {
  "0": { label: "OVERRIDE", color: "red" },
  "1": { label: "ANONYMIZE", color: "yellow" },
  "2": { label: "WARN", color: "orange" },
};

// Safety code colors
export const SAFETY_CODE_COLORS: Record<string, string> = {
  SAFE: "green",
  PII_DETECTED: "red",
  TOXICITY_DETECTED: "red",
  COMPETITOR_MENTIONED: "yellow",
  PROMPT_INJECTION: "red",
  GENERIC_UNSAFE: "red",
};

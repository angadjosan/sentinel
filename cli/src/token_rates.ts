export const TOKEN_RATES: Record<string, { input: number; output: number }> = {
  "anthropic/claude-opus-4-8": { input: 15.0, output: 75.0 },
  "anthropic/claude-sonnet-4-6": { input: 3.0, output: 15.0 },
  "anthropic/claude-haiku-4-5": { input: 0.8, output: 4.0 },
  "openai/gpt-4o": { input: 2.5, output: 10.0 },
  "openai/gpt-4o-mini": { input: 0.15, output: 0.6 },
  "google/gemini-1.5-pro": { input: 1.25, output: 5.0 },
  "local/ollama": { input: 0.0, output: 0.0 }
};

export function estimateCost(provider: string, model: string, inputTokens: number, outputTokens: number): number {
  const rate = TOKEN_RATES[`${provider}/${model}`];
  if (!rate) return 0;
  return (inputTokens * rate.input + outputTokens * rate.output) / 1_000_000;
}

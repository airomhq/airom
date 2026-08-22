// langchain4j Anthropic builder (airomhq/airom#16).
package app;

final class Wiring {
    Object chat() {
        return AnthropicChatModel.builder()
                // airom: anthropic/model-literal
                .modelName("claude-3-5-haiku-20241022")
                .build();
    }

    void comparison() {
        // airom-ok: anthropic/model-literal
        note("claude-3-opus was evaluated and rejected");
    }

    private static void note(String s) {}
}

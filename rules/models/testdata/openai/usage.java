// Builder-pattern setters, the dominant JVM SDK style. Reproduces the shape
// airom-bench Tier S found invisible (airomhq/airom#16): a model literal
// reaching the provider through a fluent builder, no `=` or `:` in sight.
package app;

final class Wiring {
    Object chat() {
        return OpenAiChatModel.builder()
                // airom: openai/model-literal
                .modelName("gpt-4o-mini")
                .temperature(0.2)
                .build();
    }

    void notAModel() {
        // airom-ok: openai/model-literal
        log("gpt-5 rumors are not a dependency");
    }

    private static void log(String s) {}
}

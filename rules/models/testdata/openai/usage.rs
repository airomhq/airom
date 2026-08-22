// Rust builder chains, the async-openai style (airomhq/airom#16).
fn request() -> CreateChatCompletionRequest {
    CreateChatCompletionRequestArgs::default()
        // airom: openai/model-literal
        .model("gpt-4o-mini")
        .max_tokens(256u32)
        .build()
        .unwrap()
}

fn not_a_dependency() {
    // airom-ok: openai/model-literal
    eprintln!("gpt-4o-mini pricing changed");
}

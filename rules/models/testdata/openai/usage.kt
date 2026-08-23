// Kotlin value-class wrapping, the aallam SDK style (airomhq/airom#16).
import com.aallam.openai.api.model.ModelId

fun request(): ChatCompletionRequest = ChatCompletionRequest(
    // airom: openai/model-literal
    model = ModelId("gpt-4o-mini"),
    messages = emptyList(),
)

fun docsOnly() {
    // airom-ok: openai/model-literal
    println("we compared gpt-4o with others in the wiki")
}

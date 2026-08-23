plugins {
    kotlin("jvm") version "2.0.0"
}

dependencies {
    implementation("dev.langchain4j:langchain4j:0.35.0")
    // The de facto Kotlin OpenAI SDK: its absence from the catalog made a
    // whole build.gradle.kts scan report nothing (airomhq/airom#17).
    implementation("com.aallam.openai:openai-client:3.8.2")
    implementation("com.google.guava:guava:33.2.1-jre")
    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

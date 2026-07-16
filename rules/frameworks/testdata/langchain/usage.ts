// LangChain JS usage fixture — positive and negative cases.
import { ChatOpenAI } from "@langchain/openai"; // airom: langchain/import
import { LLMChain } from "langchain/chains"; // airom: langchain/import

// airom: langchain/client-construct
const llm = new ChatOpenAI({ model: "gpt-4o", temperature: 0 });

// Negative cases below.

// airom-ok: langchain/import
const pkg = "not-langchain-related";

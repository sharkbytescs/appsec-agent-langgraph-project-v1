import os

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage

# Import the LLM interface for local model
from langchain_ollama import ChatOllama

# Import components from your project structure
from graph.state import SecurityAgentState
from graph.workflow import create_sast_workflow
from tools.security_tools import prepare_codebase


def main():
    """
    Main function to initialize, build, and run the multi-agent SAST workflow.
    Accepts either a local filesystem path or a GitHub URL as input1.
    If a GitHub URL is provided, it is cloned into AI_WORKSPACE and treated as local.
    """
    # 1. Load Environment Variables
    load_dotenv()
    print("Environment loaded.")

    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    print(f"OLLAMA_BASE_URL detected: {ollama_url}")

    workspace = os.getenv("AI_WORKSPACE", "")
    if workspace:
        print(f"AI_WORKSPACE detected: {workspace}")
    else:
        print(
            "WARNING: AI_WORKSPACE is not set. GitHub URL ingestion will fail until you set it in .env."
        )

    # 2. Get Project Input (local path OR GitHub URL), then resolve to local folder
    input1 = input(
        "\n[INPUT REQUIRED] Enter local project path OR GitHub URL to scan: "
    ).strip()
    if not input1:
        input1 = "."

    project_root = prepare_codebase(input1)

    if isinstance(project_root, str) and project_root.startswith("Error:"):
        raise RuntimeError(project_root)

    print(f"\nResolved project root: {project_root}")

    # 3. Initialize the LLM (The Brain)
    llm = ChatOllama(model="qwen3:4b", temperature=0.0)
    print(f"LLM initialized: {llm.model}")

    # 4. Build the Workflow (The Orchestration)
    print("Building LangGraph workflow...")
    app = create_sast_workflow(llm=llm)
    print("Workflow compiled successfully.")

    # 5. Define Initial State and Execute
    initial_state: SecurityAgentState = {
        "messages": [
            HumanMessage(
                content=f"Start SAST/SCA scan on resolved project root: {project_root}"
            )
        ],
        "code_chunk": "INITIAL_START",
        "vulnerabilities": [],
        "confirmed_vulns": [],
        "dynamic_instructions": {"project_root": project_root},
        "analysis_attempt_count": 0,
    }

    print("\n--- 🚀 Starting SAST Workflow Execution ---")
    final_state = app.invoke(initial_state)

    # 6. Output Final Results
    print("\n--- ✅ Workflow Complete ---")

    print("\nFinal Log Messages:")
    for msg in final_state["messages"][-5:]:
        print(f"  > {msg.type}: {msg.content}")

    print("\n--- Final Metrics ---")
    print(
        f"Total Analysis Attempts (Chunks Processed): {final_state['analysis_attempt_count'] - 1}"
    )
    print(f"Total Confirmed Findings: {len(final_state['confirmed_vulns'])}")
    print(f"Confirmed Vulnerabilities: {final_state['confirmed_vulns']}")


if __name__ == "__main__":
    main()

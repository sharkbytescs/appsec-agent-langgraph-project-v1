# AppSec Agent: Automated SAST and SCA Analysis

This project implements an automated security analysis agent using LangGraph to perform Static Application Security Testing (SAST) and Software Composition Analysis (SCA) on codebases. The agent leverages local LLMs (via Ollama) and specialized security tools like Semgrep and OWASP Dependency-Check to identify and confirm vulnerabilities.

## 1. Project Overview

The agent follows a multi-agent approach orchestrated by LangGraph. Each agent has a specific role in the security analysis pipeline:

1.  **Project Analysis Agent:** Determines the project's characteristics (language, tech stack) and sets initial scan strategies.
2.  **Chunking Agent:** Manages the flow of work, deciding whether to perform SCA, SAST, or finish the analysis.
3.  **Reasoning Agent:** The core analysis engine. It uses LLMs and tools (Semgrep for SAST, Dependency-Check for SCA) to find potential vulnerabilities.
4.  **Confirmer Agent:** Validates the findings from the Reasoning Agent, adding proof-of-concept details.
5.  **Reporting Agent:** Compiles the confirmed findings into a final report.

## 2. Getting Started

### 2.1. Prerequisites

*   **Python 3.8+:** Ensure you have a compatible Python version installed.
*   **Ollama:** Install Ollama and pull the `qwen3:4b` model:
    ```bash
    ollama pull qwen3:4b
    ```
*   **LangGraph, Langchain, Python dotenv:** Install the necessary Python packages:
    ```bash
    pip install -r requirements.txt 
    ```
*   **Security Tools:**
    *   **Semgrep:** Install Semgrep globally or ensure it's accessible in your PATH. See [Semgrep Installation](https://semgrep.dev/docs/installation/).
    *   **OWASP Dependency-Check:** Install OWASP Dependency-Check. See [Dependency-Check Installation](https://owasp.org/www-project-dependency-check/dependency-check-usage.html). Ensure the `dependency-check` command is available in your PATH.

### 2.2. Environment Variables

Create a `.env` file in the root of the project (`appsec-agent-project/`) with the following content:

```dotenv
# .env
OLLAMA_BASE_URL=http://127.0.0.1:11434 # Default Ollama URL
AI_WORKSPACE=/path/to/your/workspace # Directory where GitHub repos will be cloned
```

Replace `/path/to/your/workspace` with an actual directory on your system.

### 2.3. Running the Agent

Execute the main script:

```bash
python main.py
```

The script will prompt you to enter either a local project path or a GitHub URL.

## 3. Codebase Structure and Flow

### 3.1. `main.py`: The Entry Point

*   **Purpose:** Initializes the environment, sets up the LLM, takes user input for the target codebase, builds the LangGraph workflow, defines the initial state, and executes the graph.
*   **Flow:**
    1.  Loads environment variables (`.env`).
    2.  Gets the target codebase path or GitHub URL from user input using `prepare_codebase` (from `tools/security_tools.py`).
    3.  Initializes the `ChatOllama` LLM.
    4.  Calls `create_sast_workflow` (from `graph/workflow.py`) to build the LangGraph.
    5.  Defines the `initial_state` for the graph.
    6.  Invokes the compiled graph using `app.invoke(initial_state)`.
    7.  Prints the final results and a summary of findings.

### 3.2. `graph/state.py`: The Shared Memory

*   **Purpose:** Defines the structure of the `SecurityAgentState` TypedDict. This dictionary represents the shared memory that all agents in the LangGraph can access and modify.
*   **Key Fields:**
    *   `messages`: Stores the conversation history and logs. Uses `operator.add` to append messages.
    *   `code_chunk`: Holds the current piece of code or task description being processed. This is typically overwritten by the Chunking Agent.
    *   `vulnerabilities`: A list to store potential vulnerabilities found by the Reasoning Agent. Uses `operator.add`.
    *   `confirmed_vulns`: A list to store vulnerabilities that have been confirmed (e.g., with a PoC). This is managed by the Confirmer Agent.
    *   `dynamic_instructions`: A dictionary for dynamic configuration, such as determined languages or scan targets, updated by the Project Analysis Agent.
    *   `analysis_attempt_count`: A counter to track the number of analysis steps, crucial for controlling the workflow's termination.

### 3.3. `graph/workflow.py`: The Orchestrator

*   **Purpose:** Defines the structure and flow of the LangGraph application using `StateGraph`. It connects the different agent nodes and dictates the execution order based on the state.
*   **Key Components:**
    *   `route_to_next_step(state)`: This is the **coordinator** or **router** function. It inspects the `SecurityAgentState` to decide which node to move to next. It prioritizes confirming vulnerabilities, then checks if the analysis is complete, otherwise, it continues to the next chunk.
    *   `create_sast_workflow(llm)`: This function builds and compiles the graph:
        *   **Nodes:** It adds the different agent functions (`project_analysis_agent`, `chunking_agent`, `confirmer_agent`, `reporting_agent`) and the LLM-powered `reasoning_node` to the graph.
        *   **Edges:** It defines the transitions between nodes:
            *   `analysis` -> `chunking`
            *   `chunking` -> `reasoning`
            *   `confirmer` -> `reasoning` (to re-evaluate after confirmation)
            *   `reporting` -> `END`
            *   `reasoning` uses a `conditional_edge` based on `route_to_next_step` to decide between `confirmer`, `chunking`, `reporting`, or `END`.
        *   **Entry Point:** The graph starts at the `analysis` node.

### 3.4. `graph/nodes.py`: The Agent Implementations

*   **Purpose:** Contains the core logic for each agent function that acts as a node in the LangGraph.
*   **Key Agents:**
    *   `project_analysis_agent`: (Stubbed) Analyzes the project to determine languages and scan strategies. Sets `dynamic_instructions`.
    *   `chunking_agent`: Decides the next task. It initiates SCA on the first run, SAST on the second, and sets "FINISH" on the third. Updates `code_chunk` and `analysis_attempt_count`.
    *   `create_reasoning_agent_node`: This is a factory function that creates the `reasoning_node` Runnable.
        *   It binds the LLM (`ChatOllama`) with the available `ALL_SECURITY_TOOLS`.
        *   The `reasoning_node` function itself:
            *   Takes the `code_chunk` (task description) from the state.
            *   Invokes the LLM with a system prompt and the current task.
            *   If the LLM decides to use a tool (e.g., `run_semgrep_sast`, `run_dependency_check_sca`), it calls `execute_tool_call`.
            *   It then sends the tool's output back to the LLM for analysis and extraction of findings.
            *   (Stubbed) It simulates finding vulnerabilities based on the tool called.
            *   Updates the `vulnerabilities` list and adds messages to the state.
    *   `confirmer_agent`: Iterates through unconfirmed vulnerabilities, adds a placeholder Proof-of-Concept (`PoC`), and moves them to the `confirmed_vulns` list.
    *   `reporting_agent`: Generates a final, formatted report for confirmed findings.

*   **Helper Functions:**
    *   `execute_tool_call`: A utility to actually invoke the selected security tool with its arguments.

### 3.5. `tools/security_tools.py`: The External Tools

*   **Purpose:** Implements the actual security scanning tools as Langchain `@tool` decorated functions. These are the building blocks the Reasoning Agent can call.
*   **Key Tools:**
    *   `prepare_codebase(input1)`: Handles cloning GitHub repositories or resolving local paths into a usable project root. Essential for starting the analysis.
    *   `read_file(filepath)`: A basic utility to read the content of a file, used for deeper inspection if needed.
    *   `run_semgrep_sast(...)`: Executes Semgrep for SAST. It takes configuration, target path, and language as arguments.
    *   `run_dependency_check_sca(...)`: Executes OWASP Dependency-Check for SCA. It requires a project name and target path.
    *   `_looks_like_git_url`, `_repo_name_from_url`: Helper functions for `prepare_codebase`.

### 3.6. `docs/` Directory

*   **Purpose:** This directory is intended for documentation. Currently, it seems empty or not directly involved in the core execution logic.

### 3.7. `vuln-java-demo-app/` Directory

*   **Purpose:** This directory likely contains a sample Java application designed to test the security agent. It would typically include files with known vulnerabilities (e.g., weak dependencies, insecure coding patterns) to ensure the SAST and SCA tools detect them correctly.

## 4. How the Workflow Unfolds (Example Walkthrough)

1.  **`main.py` starts:** Loads env, prompts for input (e.g., a GitHub URL).
2.  **`prepare_codebase`:** Clones the repo into `AI_WORKSPACE`.
3.  **LLM & Graph Init:** `ChatOllama` is created. `create_sast_workflow` builds the LangGraph.
4.  **Initial State:** `initial_state` is created with the resolved project root.
5.  ** Execution begins:**
6.  **Workflow Ends:** The execution finishes. `main.py` prints the final state summary.

This detailed walkthrough should give you a solid foundation for your README. Let me know if you'd like any adjustments or more detail on specific parts!

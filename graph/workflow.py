import operator
from typing import Literal, Any, List

# LangGraph Imports
from langgraph.graph import StateGraph, END

# Custom Project Imports
from graph.state import SecurityAgentState

from graph.nodes import (
    project_analysis_agent,  # <-- The function name Python couldn't find before
    chunking_agent,
    confirmer_agent,
    reporting_agent,
    create_reasoning_agent_node,
    ALL_SECURITY_TOOLS,
)
from langchain_ollama import ChatOllama

# --- 1. COORDINATOR / ROUTER LOGIC ---


def route_to_next_step(
    state: SecurityAgentState,
) -> Literal["confirmer", "chunking", "reporting", END]:
    """
    The Coordinator Agent's logic (router function).
    Decides the next agent to activate based on the state.
    """

    # Check for new, unconfirmed findings
    num_vulnerabilities = len(state.get("vulnerabilities", []))
    num_confirmed = len(state.get("confirmed_vulns", []))

    # 1. PRIORITY: If we have new unconfirmed findings, confirm them first.
    if num_vulnerabilities > num_confirmed:
        print("\n[COORDINATOR]: Routing to CONFIRMER (new vulnerability found).")
        return "confirmer"

    # 2. PROGRESS CHECK: Stop after the initial SCA and SAST scans (analysis_attempt_count > 2)
    # The Chunking Agent sets its last task to "FINISH" on the 3rd attempt.
    if state["code_chunk"] == "FINISH":
        print("\n[COORDINATOR]: Analysis tasks exhausted. Routing to FINAL REPORT.")
        return "reporting"

    # 3. DEFAULT: Move to the next task (which usually means running the next chunk)
    print("\n[COORDINATOR]: Routing to CHUNKING (prepare next task).")
    return "chunking"


# --- 2. WORKFLOW CREATION FUNCTION ---


def create_sast_workflow(llm: ChatOllama):
    """
    Assembles all nodes and edges into the final LangGraph workflow.
    """

    # 1. Instantiate the Reasoning Agent Node (This requires the LLM and Tools)
    reasoning_node = create_reasoning_agent_node(llm, ALL_SECURITY_TOOLS)

    # 2. Initialize the Graph Builder
    workflow = StateGraph(SecurityAgentState)

    # 3. Add Nodes (Mapping the agent functions to named steps)
    workflow.add_node("analysis", project_analysis_agent)
    workflow.add_node("chunking", chunking_agent)
    workflow.add_node("reasoning", reasoning_node)  # LLM-powered node
    workflow.add_node("confirmer", confirmer_agent)
    workflow.add_node("reporting", reporting_agent)

    # 4. Define Edges (The Flow of Execution)

    # Path A: Initial Scan Start
    workflow.set_entry_point("analysis")

    # Path B: After Analysis, immediately get the first task/chunk
    workflow.add_edge("analysis", "chunking")

    # Path C: Chunking always leads to Reasoning to execute the task
    workflow.add_edge("chunking", "reasoning")

    # Path D: The main, looping decision point (The Coordinator)
    # The result of the reasoning agent determines the next step:
    workflow.add_conditional_edges(
        "reasoning",
        route_to_next_step,
        {
            "confirmer": "confirmer",  # Go to confirmer if new issues found
            "chunking": "chunking",  # Go back to chunking for the next task
            "reporting": "reporting",  # Go to reporting if tasks are finished
            END: END,  # Stop the process if all tasks are finished AND reported
        },
    )

    # Path E: Confirmer returns control back to Reasoning to process the findings
    # (In the stub, we jump from Confirmer back to Reasoning via a direct edge to loop)
    # Note: We return to the router function to check if the overall scan is done.
    workflow.add_edge("confirmer", "reasoning")

    # Path F: Reporting is the final step, leading to the END
    workflow.add_edge("reporting", END)

    # 5. Compile the Workflow
    return workflow.compile()

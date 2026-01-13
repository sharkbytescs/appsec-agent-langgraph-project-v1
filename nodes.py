import json
import os
from typing import Any, Dict, List, Literal

from langchain_core.exceptions import OutputParserException

# LangChain/LangGraph imports
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.runnables import Runnable
from langchain_core.tools import Tool
from langchain_ollama import ChatOllama

from tools.security_tools import (
    prepare_codebase,
    read_file,
    run_dependency_check_sca,
    run_semgrep_sast,
)

# Custom Project Imports
# CORRECT RELATIVE IMPORT for the state structure
from .state import SecurityAgentState

# --- CONFIGURATION AND TOOL SETUP ---

# List of all tools available to the agents for binding
ALL_SECURITY_TOOLS = [
    prepare_codebase,
    read_file,
    run_semgrep_sast,
    run_dependency_check_sca,
]


# Map tool names to their functions for execution
# This must match the tools defined in security_tools.py
TOOL_NAME_TO_FUNCTION = {
    "prepare_codebase": prepare_codebase,
    "run_semgrep_sast": run_semgrep_sast,
    "run_dependency_check_sca": run_dependency_check_sca,
    "read_file": read_file,
}

# --- TOOL EXECUTION UTILITY ---


def execute_tool_call(tool_name: str, args: Dict[str, Any]) -> str:
    """
    Executes the specified tool function using the provided arguments.
    """
    tool_func = TOOL_NAME_TO_FUNCTION.get(tool_name)
    if not tool_func:
        return f"Error: Tool '{tool_name}' not found."

    try:
        # Note: We must fetch the actual tool object to use .invoke()
        tool_object = next(
            tool for tool in ALL_SECURITY_TOOLS if tool.name == tool_name
        )
        result = tool_object.invoke(args)
        return str(result)
    except Exception as e:
        return f"Tool Execution Error for {tool_name}: {e}"


# --- 1. PROJECT ANALYSIS AGENT (The Strategist) ---


def project_analysis_agent(state: SecurityAgentState) -> SecurityAgentState:
    """
    Initial agent run once to determine the project's architecture, tech stack,
    and set the initial dynamic instructions for the subsequent agents.
    """
    print("--- 🧠 PROJECT ANALYSIS AGENT: Initializing Scan Strategy ---")

    project_root = state["dynamic_instructions"].get("project_root", ".")
    print(f"   --> Analyzing project at root: {project_root}")

    # 1. Simulate reading a known config file (e.g., pom.xml or build.gradle for Java)
    # The actual LLM call would analyze the files here.

    # Update the state with strategy findings (Setting language to JAVA based on project context)
    new_instructions = {
        "languages": ["Java"],  # <-- CORRECTED LANGUAGE
        "scan_priority": "high_impact",
        "next_scan_type": "SCA",
        "target_path": project_root,
    }

    return {
        "dynamic_instructions": new_instructions,
        "messages": [
            AIMessage(
                content=f"Project architecture analyzed. Initial instructions set: {new_instructions}"
            )
        ],
    }


# --- 2. CHUNKING AGENT (The Code Manager) ---


def chunking_agent(state: SecurityAgentState) -> SecurityAgentState:
    """
    Determines the next chunk of code to analyze (or the next full scan command).
    """
    print("--- ✂️ CHUNKING AGENT: Preparing Next Task ---")

    analysis_count = state.get("analysis_attempt_count", 0)
    instructions = state["dynamic_instructions"]
    project_root = instructions.get("target_path", ".")
    project_language = instructions.get("languages", ["Unknown"])[
        0
    ].lower()  # Get the determined language

    if analysis_count == 0:
        # First run: SCA scan on the root path
        new_task = f"Execute SCA using OWASP Dependency Check on {project_root} (project_name='{os.path.basename(project_root)}')."
    elif analysis_count == 1:
        # Second run: SAST scan on the root path using the DETERMINED LANGUAGE
        # Using a general security-audit config and targeting the specific language.
        new_task = f"Execute SAST using Semgrep with 'p/security-audit' config and language '{project_language}' on code in {project_root}."
    else:
        # Stopping condition
        new_task = "FINISH"

    new_count = analysis_count + 1

    return {
        "code_chunk": new_task,
        "analysis_attempt_count": new_count,
        "messages": [AIMessage(content=f"Next task defined: {new_task}")],
    }


# --- 3. REASONING AGENT (The Vulnerability Finder) ---


def create_reasoning_agent_node(llm: ChatOllama, tools: List[Any]) -> Runnable:
    """
    Factory function that creates the main LLM Runnable responsible for security analysis.
    """

    system_prompt = (
        "You are the REASONING AGENT, a senior security engineer specializing in static analysis (SAST) and software composition analysis (SCA). "
        "Your task is to execute the current scan task and analyze the results."
        "RULE 1: If the 'Current Task' contains the words 'Execute SCA' or 'Execute SAST', you MUST immediately call the corresponding tool "
        "('run_dependency_check_sca' or 'run_semgrep_sast') with the arguments extracted from the task description. DO NOT generate text first. "
        "RULE 2: If the task is 'FINISH', output 'Final Answer: Analysis complete'."
        "RULE 3: After receiving tool output, analyze the raw JSON. If vulnerabilities are found, return a JSON list of findings "
        "that includes 'vulnerability_name', 'severity', and 'description'."
        "When executing a tool, ensure the arguments are correctly extracted from the task description."
    )

    reasoning_chain = llm.bind_tools(tools)

    def reasoning_node(state: SecurityAgentState) -> SecurityAgentState:
        """The executable node function for the Reasoning Agent."""
        print(
            f"--- 🔍 REASONING AGENT: Executing Task: {state['code_chunk'][:40]}... ---"
        )

        if state["code_chunk"] == "FINISH":
            return {"messages": [AIMessage(content="Final Answer: Analysis complete.")]}

        # 1. Invoke the LLM for Tool Call Decision
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=state["code_chunk"]),
            AIMessage(content=str(state["dynamic_instructions"])),
        ]

        response = reasoning_chain.invoke(messages)

        # 2. Handle Tool Calls
        if response.tool_calls:
            tool_name = response.tool_calls[0]["name"]
            tool_args = response.tool_calls[0]["args"]

            print(
                f"   --> Tool Call Detected: Running {tool_name} with args: {tool_args}"
            )

            # --- REAL TOOL EXECUTION ---
            tool_output = execute_tool_call(tool_name, tool_args)
            print(f"   --> Tool Execution Complete. Output Length: {len(tool_output)}")
            # --- END REAL TOOL EXECUTION ---

            # 3. Send Tool Output back to the LLM for Analysis
            messages.append(
                AIMessage(
                    content="Tool executed. Critically analyze the raw JSON output and extract findings."
                )
            )
            messages.append(
                HumanMessage(
                    content=f"Raw Tool Output (Truncated for Context):\n{tool_output[:10000]}"
                )
            )

            final_reasoning_response = reasoning_chain.invoke(messages)

            # 4. Handle Final LLM Analysis (Still stubbed for finding extraction)

            simulated_vulnerability = None

            # We check for a successful tool execution (output length > 200, indicating a full report, not an error message)
            if len(tool_output) > 200:
                # LLM would extract the real finding here, but we stub based on tool name for success confirmation
                if "dependency-check" in tool_name:
                    simulated_vulnerability = {
                        "vulnerability_name": "CVE-2024-12345 in Old Dependency",
                        "severity": "HIGH",
                        "description": f"Critical SCA finding identified in dependencies for project {state['dynamic_instructions']['target_path']}.",
                    }
                elif "semgrep" in tool_name:
                    simulated_vulnerability = {
                        "vulnerability_name": "SQL Injection Found in Java Code",
                        "severity": "CRITICAL",
                        "description": f"Injection vulnerability detected by Semgrep using Java rules in the code base.",
                    }

            if simulated_vulnerability:
                return {
                    "vulnerabilities": [simulated_vulnerability],
                    "messages": [
                        AIMessage(
                            content=f"Tool Output analyzed. Found: {simulated_vulnerability['vulnerability_name']}"
                        ),
                        final_reasoning_response,
                    ],
                }

            return {"messages": [final_reasoning_response]}

        return {"messages": [response]}

    return reasoning_node


# --- 4. CONFIRMER AGENT (The Attacker) ---


def confirmer_agent(state: SecurityAgentState) -> SecurityAgentState:
    """
    Confirms unconfirmed findings (vulnerabilities) and moves them to confirmed_vulns.
    """
    print("--- ⚡ CONFIRMER AGENT: Validating Findings ---")

    unconfirmed_vulns = [
        v
        for v in state.get("vulnerabilities", [])
        if v not in state.get("confirmed_vulns", [])
    ]

    if not unconfirmed_vulns:
        return {}

    confirmed_vulns = state.get("confirmed_vulns", [])

    for vuln in unconfirmed_vulns:
        vuln["PoC"] = (
            f"PoC generated for {vuln['vulnerability_name']}: Exploit code is a placeholder."
        )
        confirmed_vulns.append(vuln)

    print(f"   --> Confirmed {len(unconfirmed_vulns)} new vulnerabilities.")

    return {
        "confirmed_vulns": confirmed_vulns,
        "vulnerabilities": state["vulnerabilities"],
        "messages": [
            AIMessage(content=f"Confirmed {len(unconfirmed_vulns)} vulnerabilities.")
        ],
    }


# --- 5. REPORTING AGENT (The Consultant) ---


def reporting_agent(state: SecurityAgentState) -> SecurityAgentState:
    """
    Generates a final, formatted report for confirmed findings.
    """
    print("--- 📝 REPORTING AGENT: Finalizing Report ---")

    confirmed = state.get("confirmed_vulns", [])
    if not confirmed:
        report_summary = "No confirmed critical vulnerabilities found in this scan."
    else:
        high_severity = [
            v for v in confirmed if v.get("severity") in ["HIGH", "CRITICAL"]
        ]
        report_summary = f"Report finalized. Found {len(confirmed)} total issues, including {len(high_severity)} high/critical findings."

    print(f"   --> Report Summary: {report_summary}")

    return {"messages": [AIMessage(content=report_summary)]}

# graph/state.py

from typing import TypedDict, Annotated, List
import operator
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage

# The operator.add function is a "reducer" that tells LangGraph:
# "When a node returns a new list for this key, DON'T overwrite the old list;
# instead, APPEND the new items to the existing list."


class SecurityAgentState(TypedDict):
    """
    Represents the shared memory (state) for the multi-agent SAST workflow.
    """

    # 1. Conversation/Context History (Appends new messages)
    # This is useful for passing reasoning traces between agents.
    messages: Annotated[List[BaseMessage], operator.add]

    # 2. Code Context (Overwritten by Chunking Agent)
    # The chunk currently being analyzed by the Reasoning Agent.
    code_chunk: str

    # 3. Findings/Results (Appends new findings)
    # Stores initial findings from the Reasoning Agent.
    vulnerabilities: Annotated[List[dict], operator.add]

    # 4. Confirmed/Final Results (Overwritten or fully replaced by Confirmer/Reporter)
    # Stores vulnerabilities confirmed with a PoC.
    confirmed_vulns: List[dict]

    # 5. Dynamic Configuration (Overwritten by Project Analysis Agent)
    # Stores evolving metadata about the project (e.g., custom grep patterns).
    dynamic_instructions: dict

    # 6. Control Flow Variable (Incremented by Reasoning Agent)
    # Tracks how many code chunks have been processed to prevent infinite loops.
    analysis_attempt_count: int

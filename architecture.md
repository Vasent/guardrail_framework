# Mental Wellness Assistant with Guardrails -- Architecture

## How It Works

```
User types how they feel
        |
        v
  [regex_input_guard] -- scans for PII, injection attacks (instant)
        |
        v
  [nlp_input_guard] -- LLM checks intent: toxic? off-topic? (1 sec)
        |
        v
  [process_request] -- generates wellness advice
        |
        v
  [guardrail_agent] -- AI reviews response: APPROVE / MODIFY / BLOCK
        |
        v
  [regex_output_guard] -- scans output for PII leaks, redacts them
        |
        v
  [nlp_output_guard] -- LLM checks: is this advice safe? (1 sec)
        |
        v
  Final output printed to user (or blocked message)
```

## Interactive Mode

```
$ python guardrails_wellness_graph.py

  =======================================================
    MENTAL WELLNESS ASSISTANT (with Guardrails)
  =======================================================

    Tell me how you're feeling. Your input will pass
    through 5 guardrail checkpoints before you see
    the response.

    Type 'demo' to run test scenarios.
    Type 'quit' to exit.

    How are you feeling? > I feel anxious and can't focus
    ...guardrails run...
    WELLNESS PRACTICE
    ...

    How are you feeling? > demo
    ...runs 5 test scenarios...

    How are you feeling? > quit
    Take care of yourself. Goodbye!
```

## Graph Structure (Detailed)

```
                    +-------+
                    | START |
                    +---+---+
                        |
                        v
            +-----------+-----------+
            |  regex_input_guard    |
            |                       |
            | Scans for:            |
            |  - Phone numbers      |
            |  - Email addresses    |
            |  - SSNs, credit cards |
            |  - SQL injection      |
            |  - Prompt injection   |
            +-----------+-----------+
                        |
               CONDITIONAL EDGE
              /                  \
         [FAIL]               [PASS]
            |                     |
            v                     v
   +--------+--------+  +--------+--------+
   | blocked_response |  | nlp_input_guard |
   +---------+--------+  |                 |
             |            | LLM classifies: |
             v            |  - Toxic?       |
           [END]          |  - Off-topic?   |
                          |  - Self-harm?   |
                          +--------+--------+
                                   |
                          CONDITIONAL EDGE
                         /                  \
                    [FAIL]               [PASS]
                       |                     |
                       v                     v
              (to blocked)        +----------+----------+
                                  |  process_request    |
                                  |                     |
                                  | Generates wellness  |
                                  | advice using LLM    |
                                  +----------+----------+
                                             |
                                             v
                                  +----------+----------+
                                  |  guardrail_agent    |
                                  |                     |
                                  | Reviews response:   |
                                  |  APPROVE = pass     |
                                  |  MODIFY  = fix it   |
                                  |  BLOCK   = reject   |
                                  +----------+----------+
                                             |
                                    CONDITIONAL EDGE
                                   /                  \
                             [BLOCK]               [PASS]
                                |                     |
                                v                     v
                       (to blocked)       +-----------+-----------+
                                          | regex_output_guard    |
                                          |                       |
                                          | Scans output for PII  |
                                          | REDACTS (not blocks)  |
                                          +-----------+-----------+
                                                      |
                                                      v
                                          +-----------+-----------+
                                          | nlp_output_guard      |
                                          |                       |
                                          | LLM checks: is advice |
                                          | safe and responsible? |
                                          +-----------+-----------+
                                                      |
                                             CONDITIONAL EDGE
                                            /                  \
                                       [FAIL]               [PASS]
                                          |                     |
                                          v                     v
                                 (to blocked)       +-----------+-----------+
                                                    | deliver_response      |
                                                    |                       |
                                                    | All 5 guardrails      |
                                                    | passed! Deliver safe  |
                                                    | response to user.     |
                                                    +-----------+-----------+
                                                                |
                                                                v
                                                          +-----+-----+
                                                          |    END    |
                                                          +-----------+
```

## State Fields

```
GuardrailState
|
|-- user_feeling            <-- set by user input
|-- regex_input_passed      <-- written by regex_input_guard
|-- regex_input_flags       <-- written by regex_input_guard
|-- nlp_input_passed        <-- written by nlp_input_guard
|-- nlp_input_reason        <-- written by nlp_input_guard
|-- raw_response            <-- written by process_request
|-- agent_guard_passed      <-- written by guardrail_agent
|-- agent_guard_action      <-- written by guardrail_agent (APPROVE/MODIFY/BLOCK)
|-- agent_guard_reason      <-- written by guardrail_agent
|-- reviewed_response       <-- written by guardrail_agent (or regex_output_guard)
|-- regex_output_flags      <-- written by regex_output_guard
|-- nlp_output_passed       <-- written by nlp_output_guard
|-- nlp_output_reason       <-- written by nlp_output_guard
|-- final_response          <-- written by deliver_response or blocked_response
|-- blocked_message         <-- written by any blocking guardrail
|-- messages                <-- appended by ALL nodes (operator.add)
```

## Three Guardrail Types Comparison

| Feature | Regex Guard | NLP Guard | Agent Guard |
|---------|------------|-----------|-------------|
| Speed | Instant (microseconds) | ~1 second (LLM call) | ~2 seconds (LLM call) |
| Cost | Free (no API call) | $ (one LLM call) | $$ (one LLM call) |
| Intelligence | Pattern matching only | Understands context | Reasons about input+output |
| Actions | Pass / Block | Pass / Block | Approve / Modify / Block |
| Best For | PII, injections, known patterns | Intent, tone, topic relevance | Response quality, appropriateness |
| Weakness | Cannot understand meaning | Binary (safe/unsafe only) | Most expensive |

## LangGraph Concepts Used

| Concept | Where in Code | What It Does |
|---------|--------------|--------------|
| State (Pydantic) | `GuardrailState` class | Typed data that flows through every node |
| Nodes | `regex_input_guard`, `nlp_input_guard`, etc. | Functions that check safety and return updates |
| Conditional Edges | `route_after_regex_input()`, etc. | Routes to "continue" or "block" based on guardrail result |
| Sequential Pipeline | Edge chain from START to END | Each guardrail runs in order |
| Graph Compilation | `graph.compile()` | Turns graph definition into runnable `app` |
| Invocation | `app.invoke({...})` | Runs the graph with initial state |
| Message Accumulation | `Annotated[list, operator.add]` | All nodes append to audit trail |

## Tech Stack

| Component | Purpose |
|-----------|---------|
| LangGraph | Graph orchestration -- nodes, edges, conditional routing |
| LangChain | OpenAI LLM wrapper (ChatOpenAI) |
| OpenAI | gpt-4o-mini -- cheap, fast, good enough for demo |
| Pydantic | State validation and type safety |
| python-dotenv | Load OPENAI_API_KEY from .env |
| re (stdlib) | Regex pattern matching for regex guardrails |

## File Structure

```
Guardrails_AgentFramework/
|-- guardrails_wellness_graph.py  Main code (graph + interactive loop)
|-- architecture.md               This file
|-- architecture.drawio           Visual diagram (open with draw.io extension)
|-- README.md                     Documentation with security analogy
|-- requirements.txt              4 dependencies
|-- .env                          OPENAI_API_KEY (not committed)
|-- .env.example                  Template for .env
|-- .gitignore                    Ignores .env, venv, __pycache__
```

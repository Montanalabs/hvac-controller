#! VULNERABLE hvac-controller — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant setMode

let raw = fetch<web>
privileged { setMode(raw) }  # tainted -> tool: REJECTED

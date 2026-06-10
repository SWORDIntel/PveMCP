import asyncio
import inspect
from functools import wraps
from pathlib import Path
from typing import Any
from lupa import LuaRuntime

WORKFLOW_DIR = Path("src/pvemcp/workflows")

class LuaWorkflowEngine:
    def __init__(self):
        self.runtime = LuaRuntime(unpack_returned_tuples=True)

    def bind_tool(self, name: str, func: Any):
        """Bind a Python tool function to the Lua runtime, wrapping async functions if needed."""
        if inspect.iscoroutinefunction(func):
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                # Workflows are called from sync tools in thread pools, so a new loop is safe
                return asyncio.run(func(*args, **kwargs))
            self.runtime.globals()[name] = sync_wrapper
        else:
            self.runtime.globals()[name] = func

    def run_script(self, script_name: str) -> Any:
        script_path = WORKFLOW_DIR / f"{script_name}.lua"
        if not script_path.exists():
            raise FileNotFoundError(f"Workflow {script_name} not found.")
        
        script = script_path.read_text()
        return self.runtime.execute(script)

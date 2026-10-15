import anyio
from pathlib import Path
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

ROOT = Path(__file__).resolve().parent
PNPM = r"C:\Users\Admin\.cache\codex-runtimes\codex-primary-runtime\dependencies\bin\fallback\pnpm.cmd"

async def main():
    parameters = StdioServerParameters(command=PNPM, args=["--dir", str(ROOT), "exec", "mcp-server-filesystem", str(ROOT / "fixture")])
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            for tool in tools.tools:
                print(tool.name, tool.input_schema)
            result = await session.call_tool("read_text_file", {"path": str(ROOT / "fixture" / "readme.txt")})
            print("READ_RESULT", result.content[0].text)

anyio.run(main)

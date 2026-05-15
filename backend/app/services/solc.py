import asyncio


class SolcSelectError(RuntimeError):
    pass


async def configure_solc(version: str | None) -> None:
    if not version:
        return
    await _run_solc_select("install", version)
    await _run_solc_select("use", version)


async def _run_solc_select(*args: str) -> None:
    process = await asyncio.create_subprocess_exec(
        "solc-select",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        detail = (stderr or stdout).decode(errors="replace").strip()
        raise SolcSelectError(f"solc-select {' '.join(args)} failed: {detail}")

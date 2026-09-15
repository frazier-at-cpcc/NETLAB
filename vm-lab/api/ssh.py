import asyncio
import logging
import subprocess

logger = logging.getLogger(__name__)


async def run_ssh_command(ip: str, user: str, password: str, command: str, timeout: int = 60) -> tuple:
    """Run a command via SSH and return (success, output)."""
    ssh_cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        f"{user}@{ip}",
        command
    ]

    try:
        result = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
            ),
            timeout=timeout + 5
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        logger.error("SSH command failed (%s)", type(e).__name__)
        return False, type(e).__name__

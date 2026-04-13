import argparse
import os
import subprocess
import sys
import time
from typing import Optional

import requests

# ── Stack definitions ──────────────────────────────────────────────────────────
#
# Each entry in STACKS describes one deployable service group:
#   name          — short identifier used on the command line
#   compose_dir   — path to the directory containing docker-compose.yml,
#                   relative to the repository root
#   health_url    — HTTP endpoint to poll after startup to confirm the service
#                   is actually accepting requests (not just "container running")
#   port          — main port the service listens on (for display only)
#   description   — one-line description shown in status output
#
# The order here matters: TheHive depends on Elasticsearch (started inside its
# compose), but Cortex has its own Elasticsearch instance. MISP is independent.
# We start TheHive last because it has the most dependencies.
STACKS = [
    {
        "name":        "misp",
        "compose_dir": "tosin-soc-project/prod1-misp/misp-docker",
        "health_url":  "https://localhost:8444",
        "port":        8444,
        "description": "Threat intelligence sharing (MISP)",
    },
    {
        "name":        "cortex",
        "compose_dir": "tosin-soc-project/prod1-cortex",
        "health_url":  "http://localhost:9001",
        "port":        9001,
        "description": "Automated analysis and response (Cortex)",
    },
    {
        "name":        "thehive",
        "compose_dir": "tosin-soc-project/prod1-thehive",
        "health_url":  "http://localhost:9000",
        "port":        9000,
        "description": "Case and incident management (TheHive)",
    },
]

# The shared Docker network allows containers from different compose stacks
# to communicate. TheHive needs to reach MISP and Cortex, so this network
# must exist before any stack is started.
SHARED_NETWORK_NAME = "soc-net"

# How many seconds to wait between health-check polls while waiting for a
# service to become ready after docker compose up.
HEALTH_POLL_INTERVAL = 5

# Maximum total seconds to wait for a service to become healthy before giving up.
HEALTH_TIMEOUT = 180

# ── ANSI colour codes ──────────────────────────────────────────────────────────
# Used to colour terminal output. Each code is a string that the terminal
# interprets as a formatting instruction rather than displaying literally.
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


# ── Helper functions ───────────────────────────────────────────────────────────

def repo_root() -> str:
    """
    Return the absolute path to the repository root.

    Defaults to the directory containing this script, which is correct when
    the script lives at the repo root. Can be overridden with SOC_REPO_ROOT
    for cases where the script is invoked from a different working directory.
    """
    return os.getenv(
        "SOC_REPO_ROOT",
        os.path.dirname(os.path.abspath(__file__))
    )


def resolve_stacks(names: Optional[list]) -> list:
    """
    Return a filtered list of stack definitions matching the given names.

    If names is None or empty, return all stacks (the default for most commands).
    If one or more names are given, validate each one and exit with an error
    message if an unrecognised name is provided.

    This lets users run `python3 soc_launcher.py start thehive cortex` to
    start just those two stacks without touching MISP.
    """
    if not names:
        return STACKS

    valid_names = {s["name"] for s in STACKS}
    requested   = []
    for name in names:
        if name not in valid_names:
            print(f"{RED}Unknown stack: '{name}'{RESET}")
            print(f"  Valid options: {', '.join(sorted(valid_names))}")
            sys.exit(1)
        # Find and append the matching stack definition dict
        requested.append(next(s for s in STACKS if s["name"] == name))
    return requested


def run(cmd: list, cwd: str, capture: bool = False) -> subprocess.CompletedProcess:
    """
    Execute a shell command in a given working directory.

    Parameters:
        cmd     — list of command tokens (e.g. ["docker", "compose", "up", "-d"])
        cwd     — directory to run the command in
        capture — if True, capture stdout/stderr instead of printing them live

    Prints the command before running it so users can see exactly what is being
    executed (important for a launcher script — no hidden magic).

    Returns the CompletedProcess result so callers can inspect returncode,
    stdout, and stderr.
    """
    print(f"{DIM}  $ {' '.join(cmd)}{RESET}")
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=capture,
        text=True,  # return str instead of bytes for stdout/stderr
    )


def check_docker() -> bool:
    """
    Verify that Docker is installed and the Docker daemon is running.

    Returns True if both are available, False otherwise.
    We check for the daemon by running `docker info`, which fails if the
    daemon is not reachable (e.g. Docker Desktop is closed on Windows/Mac).
    """
    # Check if the docker binary exists in PATH
    result = subprocess.run(["which", "docker"], capture_output=True)
    if result.returncode != 0:
        print(f"{RED}Docker is not installed or not in PATH.{RESET}")
        print("  Install Docker: https://docs.docker.com/get-docker/")
        return False

    # Check if the Docker daemon is running
    result = subprocess.run(["docker", "info"], capture_output=True)
    if result.returncode != 0:
        print(f"{RED}Docker daemon is not running.{RESET}")
        print("  Start Docker Desktop or run: sudo systemctl start docker")
        return False

    return True


def ensure_shared_network() -> None:
    """
    Create the shared Docker bridge network if it does not already exist.

    The soc-net network allows containers from different docker-compose stacks
    to reach each other by hostname. For example, the TheHive container
    uses hostname "misp-core" to query MISP, which only works if both
    containers are on the same network.

    This function is idempotent — running it when the network already exists
    is harmless.
    """
    print(f"\n{CYAN}Checking shared network '{SHARED_NETWORK_NAME}'...{RESET}")

    # Check if the network already exists by inspecting it; exit code 0 = exists
    result = subprocess.run(
        ["docker", "network", "inspect", SHARED_NETWORK_NAME],
        capture_output=True
    )

    if result.returncode == 0:
        print(f"  {GREEN}✓{RESET} Network '{SHARED_NETWORK_NAME}' already exists")
    else:
        # Network does not exist — create it
        print(f"  Creating network '{SHARED_NETWORK_NAME}'...")
        create_result = subprocess.run(
            ["docker", "network", "create", SHARED_NETWORK_NAME]
        )
        if create_result.returncode == 0:
            print(f"  {GREEN}✓{RESET} Network created")
        else:
            print(f"  {RED}✗ Failed to create network. Check Docker permissions.{RESET}")
            sys.exit(1)


def wait_for_health(stack: dict, timeout: int = HEALTH_TIMEOUT) -> bool:
    """
    Poll a stack's health endpoint until it responds or the timeout expires.

    After `docker compose up -d` returns, the containers are running but the
    application inside may still be initialising (Elasticsearch, Cassandra, and
    TheHive all take 30–120 seconds on first boot). We poll the health URL
    so we can report when the service is actually ready to accept requests.

    Parameters:
        stack   — stack definition dict containing health_url and name
        timeout — maximum seconds to wait before declaring startup failed

    Returns True if the service responded within the timeout, False otherwise.
    """
    url       = stack["health_url"]
    name      = stack["name"]
    elapsed   = 0
    # Use a spinner to show the user something is happening while they wait
    spinner   = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"]
    spin_idx  = 0

    print(f"\n  Waiting for {name} to become ready (timeout: {timeout}s)...")

    while elapsed < timeout:
        try:
            # verify=False suppresses SSL certificate warnings for MISP's self-signed cert
            response = requests.get(url, timeout=3, verify=False)
            # Any HTTP response (even 401 Unauthorized) means the app is up
            if response.status_code in (200, 301, 302, 401, 403):
                print(f"\r  {GREEN}✓{RESET} {name} is ready "
                      f"(HTTP {response.status_code} after {elapsed}s)   ")
                return True
        except requests.exceptions.RequestException:
            # Connection refused or timeout — service not ready yet, keep waiting
            pass

        # Animate the spinner to reassure the user the script hasn't hung
        print(f"\r  {spinner[spin_idx % len(spinner)]} Waiting... "
              f"{elapsed}s elapsed", end="", flush=True)
        spin_idx += 1
        time.sleep(HEALTH_POLL_INTERVAL)
        elapsed += HEALTH_POLL_INTERVAL

    # Timed out
    print(f"\r  {YELLOW}! {name} did not respond within {timeout}s.{RESET}  ")
    print(f"    It may still be initialising. Check logs with:")
    print(f"    python3 soc_launcher.py logs {name}")
    return False


def print_header(title: str) -> None:
    """Print a formatted section header with a cyan accent line."""
    print(f"\n{BOLD}{CYAN}{'─' * 50}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 50}{RESET}")


# ── Command handlers ───────────────────────────────────────────────────────────

def cmd_start(stacks: list, wait: bool = True) -> None:
    """
    Start one or more stacks using `docker compose up -d`.

    Steps:
        1. Verify Docker is running
        2. Create the shared network if needed
        3. For each stack: run docker compose up -d in its directory
        4. Optionally poll the health endpoint until the service is ready

    The -d flag runs containers in detached mode (background), so the command
    returns immediately after the containers are started, even though the
    applications inside may still be initialising.
    """
    print_header("Starting SOC Stacks")

    if not check_docker():
        sys.exit(1)

    ensure_shared_network()

    root = repo_root()
    for stack in stacks:
        compose_path = os.path.join(root, stack["compose_dir"])
        print(f"\n{BOLD}Starting {stack['name']}...{RESET}")
        print(f"  {DIM}{stack['description']}{RESET}")

        # Verify the compose directory actually exists before trying to run it
        if not os.path.isdir(compose_path):
            print(f"  {RED}✗ Directory not found: {compose_path}{RESET}")
            print(f"    Run from the repository root, or set SOC_REPO_ROOT.")
            continue

        # `docker compose up -d` starts containers in detached (background) mode.
        # --remove-orphans cleans up containers from removed services in the compose file.
        result = run(
            ["docker", "compose", "up", "-d", "--remove-orphans"],
            cwd=compose_path
        )

        if result.returncode != 0:
            print(f"  {RED}✗ docker compose up failed for {stack['name']}.{RESET}")
            print(f"    Check the compose file at: {compose_path}")
            continue

        print(f"  {GREEN}✓{RESET} Containers started for {stack['name']}")

        # Poll the health URL to confirm the application is actually serving requests
        if wait:
            wait_for_health(stack)

    # Print the access URLs at the end so they're easy to find
    print(f"\n{BOLD}Access URLs:{RESET}")
    for stack in stacks:
        print(f"  {stack['name']:<12} → {stack['health_url']}")

    print(f"\n{DIM}Hint: Run  python3 soc_launcher.py status  to see service health.{RESET}\n")


def cmd_stop(stacks: list) -> None:
    """
    Stop one or more stacks using `docker compose down`.

    `docker compose down` stops and removes the containers but preserves
    the data volumes (Cassandra data, Elasticsearch indices, etc.) so that
    data is not lost between sessions.

    Note: This does NOT remove volumes. To reset data completely, you would
    need to add `--volumes` to the docker compose down command or use the
    init scripts in each stack's scripts/ directory.
    """
    print_header("Stopping SOC Stacks")

    root = repo_root()
    for stack in stacks:
        compose_path = os.path.join(root, stack["compose_dir"])
        print(f"\n{BOLD}Stopping {stack['name']}...{RESET}")

        if not os.path.isdir(compose_path):
            print(f"  {YELLOW}! Directory not found: {compose_path} — skipping{RESET}")
            continue

        # docker compose down stops containers and removes them.
        # Data volumes are preserved (no --volumes flag).
        result = run(["docker", "compose", "down"], cwd=compose_path)

        if result.returncode == 0:
            print(f"  {GREEN}✓{RESET} {stack['name']} stopped")
        else:
            print(f"  {RED}✗ Failed to stop {stack['name']}{RESET}")

    print()


def cmd_status(stacks: list) -> None:
    """
    Show the running state and health of all stacks.

    For each stack we do two things:
        1. Run `docker compose ps` to see the container states (from Docker)
        2. Make an HTTP request to the health URL to confirm the application
           is actually serving (a container can be "running" but the app inside
           may have crashed)
    """
    print_header("SOC Stack Status")

    root = repo_root()
    for stack in stacks:
        compose_path = os.path.join(root, stack["compose_dir"])
        print(f"\n{BOLD}{stack['name'].upper()}{RESET}  {DIM}({stack['description']}){RESET}")

        if not os.path.isdir(compose_path):
            print(f"  {YELLOW}! Compose directory not found{RESET}")
            continue

        # Get container states from Docker
        # --format table trims the output to essential columns
        result = run(
            ["docker", "compose", "ps", "--format", "table"],
            cwd=compose_path,
            capture=True   # capture so we can format/indent the output
        )

        if result.stdout.strip():
            # Indent each line of docker compose ps output for readability
            for line in result.stdout.strip().split("\n"):
                print(f"  {line}")
        else:
            print(f"  {DIM}No containers running{RESET}")

        # Check if the application's HTTP endpoint is responding
        try:
            import urllib3
            urllib3.disable_warnings()  # suppress SSL warnings for MISP
            resp = requests.get(stack["health_url"], timeout=3, verify=False)
            if resp.status_code in (200, 301, 302, 401, 403):
                print(f"  {GREEN}● HTTP health check: OK "
                      f"(HTTP {resp.status_code}){RESET}")
            else:
                print(f"  {YELLOW}● HTTP health check: unexpected status "
                      f"({resp.status_code}){RESET}")
        except requests.exceptions.ConnectionError:
            print(f"  {RED}● HTTP health check: NOT REACHABLE "
                  f"({stack['health_url']}){RESET}")
        except requests.exceptions.Timeout:
            print(f"  {YELLOW}● HTTP health check: timeout{RESET}")

    print()


def cmd_restart(stacks: list) -> None:
    """
    Stop all specified stacks then start them again.

    This is a convenience wrapper around cmd_stop + cmd_start.
    Useful when configuration files have been changed and you need a clean
    restart to pick up the new settings.
    """
    print_header("Restarting SOC Stacks")
    # Stop in reverse order (TheHive first, MISP last) to avoid connection errors
    cmd_stop(list(reversed(stacks)))
    cmd_start(stacks)


def cmd_logs(stack_name: str, follow: bool = False, tail: int = 50) -> None:
    """
    Display recent log output from a stack's containers.

    Parameters:
        stack_name — which stack to show logs for
        follow     — if True, stream logs continuously (like `tail -f`)
        tail       — number of recent lines to show before the current point

    This is especially useful during first-time setup when a service is taking
    a long time to start — you can see exactly what it is doing.
    """
    # Resolve the stack by name
    matching = [s for s in STACKS if s["name"] == stack_name]
    if not matching:
        print(f"{RED}Unknown stack: '{stack_name}'{RESET}")
        sys.exit(1)

    stack        = matching[0]
    compose_path = os.path.join(repo_root(), stack["compose_dir"])

    if not os.path.isdir(compose_path):
        print(f"{RED}Compose directory not found: {compose_path}{RESET}")
        sys.exit(1)

    print_header(f"Logs: {stack_name}")

    # Build the docker compose logs command
    logs_cmd = ["docker", "compose", "logs", f"--tail={tail}"]
    if follow:
        # -f streams new log lines continuously until Ctrl+C
        logs_cmd.append("-f")

    print(f"{DIM}(Showing last {tail} lines"
          + (" — press Ctrl+C to stop" if follow else "") + f"){RESET}\n")

    # Run the command without capturing so logs stream directly to the terminal
    subprocess.run(logs_cmd, cwd=compose_path)


def cmd_init(stack_name: str) -> None:
    """
    Run the first-time initialisation script for a stack.

    Each stack has an init.sh script in its scripts/ directory that:
        - Generates random secrets (Elasticsearch password, TheHive secret key)
        - Creates config files from templates
        - Sets correct file permissions
        - Generates SSL certificates

    This must be run once before starting the stack for the first time.
    Running it again will warn about existing config but will not overwrite
    secrets that have already been generated.
    """
    matching = [s for s in STACKS if s["name"] == stack_name]
    if not matching:
        print(f"{RED}Unknown stack: '{stack_name}'. "
              f"Valid options: {', '.join(s['name'] for s in STACKS)}{RESET}")
        sys.exit(1)

    stack        = matching[0]
    compose_path = os.path.join(repo_root(), stack["compose_dir"])
    init_script  = os.path.join(compose_path, "scripts", "init.sh")

    if not os.path.isfile(init_script):
        print(f"{YELLOW}No init script found at: {init_script}{RESET}")
        print(f"  This stack may not require initialisation, or the path may have changed.")
        return

    print_header(f"Initialising: {stack_name}")
    print(f"{DIM}Running: bash {init_script}{RESET}\n")

    # Run bash explicitly because init.sh may not have execute permission set
    result = subprocess.run(["bash", init_script], cwd=compose_path)

    if result.returncode == 0:
        print(f"\n{GREEN}✓ Initialisation complete for {stack_name}.{RESET}")
        print(f"  You can now start the stack with:")
        print(f"  python3 soc_launcher.py start {stack_name}")
    else:
        print(f"\n{RED}✗ Initialisation failed for {stack_name}.{RESET}")
        print(f"  Check the output above for error messages.")


def cmd_init_all() -> None:
    """
    Run first-time initialisation for all three stacks in sequence.

    Called when the user runs `python3 soc_launcher.py init` without specifying
    a stack name. Initialises MISP, Cortex, and TheHive in that order.
    """
    print_header("First-Time Setup — Initialising All Stacks")
    print(f"{DIM}This will generate secrets and config files for all stacks.{RESET}\n")
    for stack in STACKS:
        cmd_init(stack["name"])
    print(f"\n{GREEN}{BOLD}Setup complete.{RESET} Start the platform with:")
    print(f"  python3 soc_launcher.py start\n")


# ── Argument parser ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the argument parser for the launcher CLI.

    The CLI uses subcommands (start, stop, status, etc.) so each command can
    have its own set of options. This is the same pattern used by git, docker,
    and other CLI tools.
    """
    parser = argparse.ArgumentParser(
        prog="soc_launcher.py",
        description="Catnip Games SOC Platform — Stack Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 soc_launcher.py start                # start all stacks
  python3 soc_launcher.py start thehive        # start TheHive only
  python3 soc_launcher.py start misp cortex    # start two specific stacks
  python3 soc_launcher.py stop                 # stop all stacks
  python3 soc_launcher.py status               # check what is running
  python3 soc_launcher.py logs thehive         # see TheHive log output
  python3 soc_launcher.py logs thehive -f      # stream logs live
  python3 soc_launcher.py init                 # first-time setup (all stacks)
  python3 soc_launcher.py init thehive         # first-time setup for one stack
  python3 soc_launcher.py restart              # stop then start everything

Available stack names: misp, cortex, thehive
        """,
    )

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True  # exit with usage message if no subcommand given

    # ── start ──────────────────────────────────────────────────────────────────
    p_start = sub.add_parser("start", help="Start one or all stacks")
    p_start.add_argument(
        "stacks", nargs="*",
        help="Stack names to start (default: all). Options: misp cortex thehive"
    )
    p_start.add_argument(
        "--no-wait", action="store_true",
        help="Don't wait for health checks — return immediately after docker compose up"
    )

    # ── stop ───────────────────────────────────────────────────────────────────
    p_stop = sub.add_parser("stop", help="Stop one or all stacks")
    p_stop.add_argument(
        "stacks", nargs="*",
        help="Stack names to stop (default: all)"
    )

    # ── restart ────────────────────────────────────────────────────────────────
    p_restart = sub.add_parser("restart", help="Stop then start one or all stacks")
    p_restart.add_argument(
        "stacks", nargs="*",
        help="Stack names to restart (default: all)"
    )

    # ── status ─────────────────────────────────────────────────────────────────
    p_status = sub.add_parser("status", help="Show container state and HTTP health")
    p_status.add_argument(
        "stacks", nargs="*",
        help="Stack names to check (default: all)"
    )

    # ── logs ───────────────────────────────────────────────────────────────────
    p_logs = sub.add_parser("logs", help="Show container logs for a stack")
    p_logs.add_argument(
        "stack",
        help="Stack name: misp, cortex, or thehive"
    )
    p_logs.add_argument(
        "-f", "--follow", action="store_true",
        help="Stream logs continuously (press Ctrl+C to stop)"
    )
    p_logs.add_argument(
        "--tail", type=int, default=50,
        help="Number of recent lines to show (default: 50)"
    )

    # ── init ───────────────────────────────────────────────────────────────────
    p_init = sub.add_parser(
        "init",
        help="Run first-time initialisation (generate secrets and config files)"
    )
    p_init.add_argument(
        "stack", nargs="?",
        help="Stack name to initialise (default: all stacks)"
    )

    return parser


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Parse arguments and dispatch to the appropriate command handler.
    """
    # Suppress the InsecureRequestWarning from urllib3 that appears when we
    # make HTTPS requests to MISP's self-signed certificate. We know it's
    # self-signed and accept the risk in a development environment.
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass  # urllib3 not available — SSL warnings may appear but that's fine

    parser = build_parser()
    args   = parser.parse_args()

    # Dispatch to the appropriate handler based on the subcommand
    if args.command == "start":
        stacks = resolve_stacks(args.stacks)
        cmd_start(stacks, wait=not args.no_wait)

    elif args.command == "stop":
        stacks = resolve_stacks(args.stacks)
        cmd_stop(stacks)

    elif args.command == "restart":
        stacks = resolve_stacks(args.stacks)
        cmd_restart(stacks)

    elif args.command == "status":
        stacks = resolve_stacks(args.stacks)
        cmd_status(stacks)

    elif args.command == "logs":
        cmd_logs(args.stack, follow=args.follow, tail=args.tail)

    elif args.command == "init":
        if args.stack:
            cmd_init(args.stack)
        else:
            cmd_init_all()


if __name__ == "__main__":
    main()
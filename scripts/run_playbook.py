import json
import os
import re
import subprocess
import sys
from pathlib import Path


TARGET_ENV = 'SOFTWARE_MANAGER_TARGETS'
PLAY_HEADER = re.compile(r'^\s*play #2 \(.*\): Manage Windows software(?:\s+TAGS:.*)?$')
HOST_COUNT = re.compile(r'^\s*hosts \((\d+)\):\s*$')
HOST_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]*\Z')


def preflight(project):
    directories = ('library', 'module_utils', 'scripts')
    files = (
        'ansible.cfg', 'playbook.yml', 'task_windows.yaml',
        'library/software_manager.py', 'module_utils/software_core.py',
        'scripts/installed_software.ps1', 'scripts/filesystem.ps1',
        'scripts/package_guard.ps1', 'scripts/stop_process.ps1',
    )
    errors = []
    for name in directories:
        path = project / name
        if not path.is_dir() or not os.access(path, os.R_OK | os.X_OK):
            errors.append(str(path))
    for name in files:
        path = project / name
        if not path.is_file() or not os.access(path, os.R_OK):
            errors.append(str(path))
    if errors:
        raise RuntimeError('Missing or inaccessible controller files: ' + ', '.join(errors) +
                           '. Check group read/execute permissions for the container user.')


def parse_hosts(output):
    lines = output.splitlines()
    headers = [i for i, line in enumerate(lines) if PLAY_HEADER.fullmatch(line)]
    if len(headers) != 1:
        raise RuntimeError('Unable to identify the Windows play in ansible-playbook --list-hosts.')
    for i in range(headers[0] + 1, len(lines)):
        if re.match(r'^\s*play #\d+ ', lines[i]):
            break
        match = HOST_COUNT.fullmatch(lines[i])
        if match:
            count = int(match.group(1))
            names = [line.strip() for line in lines[i + 1:i + 1 + count]]
            if len(names) != count or any(not HOST_NAME.fullmatch(name) for name in names):
                raise RuntimeError('Invalid host list returned by ansible-playbook.')
            if len(set(names)) != count:
                raise RuntimeError('Duplicate hosts in ansible-playbook output.')
            return sorted(set(names) - {'localhost'})
    raise RuntimeError('Windows host count not found in ansible-playbook output.')


def add_option(args, option):
    index = args.index('--') if '--' in args else len(args)
    return [*args[:index], option, *args[index:]]


def select_hosts(args, limit, env):
    if limit.strip() == 'localhost':
        return []
    preview_env = dict(env, ANSIBLE_NOCOLOR='1', ANSIBLE_FORCE_COLOR='0')
    preview = subprocess.run(
        ['ansible-playbook', *add_option(args, '--list-hosts')],
        env=preview_env, stdout=subprocess.PIPE, text=True, check=False,
    )
    if preview.returncode:
        raise RuntimeError(f'Host selection failed (ansible-playbook exit code {preview.returncode}). No Windows operations started.')
    return parse_hosts(preview.stdout)


def ensure_ansible_python():
    result = subprocess.run(
        ['ansible-playbook', '--version'],
        stdout=subprocess.PIPE, text=True, check=False,
    )
    if result.returncode:
        raise RuntimeError(f'Unable to determine Ansible Python (exit code {result.returncode}).')
    match = re.search(r'^\s*python version\s*=.*\((/[^()\r\n]+)\)\s*$', result.stdout, re.MULTILINE)
    if not match:
        raise RuntimeError('Unable to determine Python interpreter from ansible-playbook --version.')
    interpreter = match.group(1)
    if not os.path.isfile(interpreter) or not os.access(interpreter, os.X_OK):
        raise RuntimeError(f'Ansible Python interpreter is not executable: {interpreter}')
    if os.path.abspath(sys.executable) != os.path.abspath(interpreter):
        os.execv(interpreter, [interpreter, str(Path(__file__).resolve()), *sys.argv[1:]])


def main(args):
    project = Path(__file__).resolve().parent.parent
    preflight(project)
    from ansible.cli.playbook import PlaybookCLI
    cli = PlaybookCLI(['ansible-playbook', *args])
    cli.init_parser()
    options = cli.parser.parse_args(args)
    if len(options.args) != 1 or Path(options.args[0]).resolve() != project / 'playbook.yml':
        raise RuntimeError('Run playbook.yml separately through this launcher.')
    skipped_tags = {tag.strip() for item in (options.skip_tags or []) for tag in item.split(',')}
    if options.start_at_task or options.step or skipped_tags.intersection({'always', 'all'}):
        raise RuntimeError('Options that can skip required localhost tasks are not supported for playbook.yml.')
    env = dict(os.environ)
    env.pop(TARGET_ENV, None)
    limit = options.subset
    if limit and not options.syntax:
        if not limit.strip():
            raise RuntimeError('Empty or whitespace-only --limit is not supported.')
        hosts = select_hosts(args, limit, env)
        env[TARGET_ENV] = json.dumps([*hosts, 'localhost'])
        args = add_option(args, '--limit=')
    os.execvpe('ansible-playbook', ['ansible-playbook', *args], env)


if __name__ == '__main__':
    try:
        ensure_ansible_python()
        main(sys.argv[1:])
    except (OSError, RuntimeError, ImportError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(2)

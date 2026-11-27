# Windows software manager

[English](README.md) | [Русский](README.ru.md)

The main playbook is `playbook.yml`. Apply all files from the current archive together, on top of the version after the renaming. Inventory, logs, fact caches, collections, and secrets are not included in the archive. No existing files need to be deleted if the renaming has already been completed.

## Architecture

- `library/software_manager.py` — local Ansible Python module (`AnsibleModule`, without private Action Plugin APIs). Runs on the controller; Python is not required on Windows.
- `module_utils/software_core.py` — pattern validation and merging, version selection, SHA-256, planning, safe ZIP/TAR handling, package verification, and state database conversion.
- `playbook.yml` — three plays: localhost catalog, independent Windows processing (`strategy: free`), and localhost reporting.
- `task_*.yaml` — operations using standard modules, PRE/POST hooks, error handling, and check mode.
- `scripts/*.ps1` — registry inspection, file verification, and atomic writes of state and templates.
- `telegram.yaml` — final report.

## Requirements and execution

Target collection versions are pinned in `requirements.yml`. These versions require ansible-core >= 2.16; the minimum version is not a recommendation to use an outdated release. Check the compatibility of the selected EE with its Python and collections. Windows PowerShell 5.1+ with WinRM is required. The controller requires Docker and flock when using `run.sh`, as well as msitools (`msiinfo`) and the `pefile` library in the Python environment used by Ansible.

`run.sh` automatically prepares a derived Execution Environment. The defaults are `ANSIBLE_EE_IMAGE=ansible-ee:metadata` (final image) and `ANSIBLE_EE_BASE_IMAGE=quay.io/ansible/awx-ee:latest` (base image). If the final image exists locally, it is used and saved to an archive if the archive is missing. If the image is missing, it is restored from the `.tar.gz` archive (or the previous `.tar`, which is compressed). If neither the image nor the archive exists, the script pulls the base image if missing, builds the final image using the Dockerfile, and atomically saves it in `.docker-images/` as TAR.GZ. No additional `docker load` is needed after the build. An explicit `ANSIBLE_EE_IMAGE` digest reference denotes a prebuilt image: if neither a local copy nor an archive exists, it is pulled rather than built. Without `msiinfo` or `pefile`, indexing fails before Windows operations are performed. For reproducibility, specify a fixed tag or digest using `ANSIBLE_EE_BASE_IMAGE`. The local image and existing archive are not updated automatically; changes to the Dockerfile or base image alone do not trigger a rebuild. To rebuild, use a new `ANSIBLE_EE_IMAGE` tag or manually remove the old final image and its archive (including the previous `.tar`, if present). If restoring from the archive fails, execution stops without automatically pulling an image. The archive directory can be changed via `ANSIBLE_EE_CACHE_DIR`. If collections are already installed, retain `.ansible/collections`. If needed, install the pinned dependencies in an agreed environment (the command may contact Galaxy):

```bash
ansible-galaxy collection install -r requirements.yml -p .ansible/collections
```

Example without Docker, from the project root on a controller with access to `/source`:

```bash
ansible-playbook -i inventory.yaml playbook.yml --check --diff
ansible-playbook -i inventory.yaml playbook.yml --limit 'test-host,localhost' --check
```

Using Docker (from the project directory, without a prior manual build):

```bash
./run.sh --limit test-host --check
```

The Dockerfile targets the existing CentOS Stream 9 with Python 3.12. Installing RPMs from EPEL and wheels from PyPI requires access to the corresponding repositories during the first build; subsequent runs using a prebuilt image or archive do not download dependencies. The Dockerfile is passed to the builder via stdin without a filesystem context: inventory and project files are not sent to the Docker builder. The current Dockerfile does not use COPY/ADD for local files; adding such instructions requires changing how the context is passed. For manual builds using a directory, `.dockerignore` limits the context to the Dockerfile and `.dockerignore` itself.

For the AWX EE container (UID 1000, GID 0), source files must be readable by the root group and directories must be traversable. If extracting over existing directories with mode 0700, adjust them manually without changing permissions on inventory or secrets:

```bash
chmod g+rx library module_utils scripts
chmod g+r library/*.py module_utils/*.py scripts/*.ps1 scripts/run_playbook.py task_windows.yaml playbook.yml
```

`scripts/run_playbook.py` determines the interpreter using `ansible-playbook --version` and restarts itself with that interpreter if necessary. This allows the Python environment containing Ansible to be used even if `python3` in the image points to a different version. `run.sh` sets `HOME=/tmp` and `ANSIBLE_LOCAL_TEMP=/tmp/ansible-local`; required file accessibility is checked as the container user before Ansible starts.

```bash
export SOURCE_DIR=/mnt/hdd1/shares/autodownloads
./run.sh playbook.yml --limit 'test-host' --check
./run.sh playbook.yml --limit 'test-host'
```

Replace the host name with a real value. When running the main playbook through `run.sh`, `--limit` applies only to Windows hosts: `scripts/run_playbook.py` determines the exact list using standard `ansible-playbook --list-hosts`, then passes it to the main play. `localhost` is added automatically and does not execute Windows tasks. It is included in the main play as a service host so that ordinary failures on all Windows hosts do not prevent the final play from running. When running `ansible-playbook` directly, explicitly include localhost and use a compatible positive limit. The final play is not guaranteed to run if preparation fails, the limit is invalid, the process terminates unexpectedly, or the controller fails. `--start-at-task`, `--step`, and skipping `always`/`all` are not permitted for the main playbook. Argument handling was verified against ansible-core 2.18.17 source code; preliminary host selection with a limit may prompt for the Vault password again. Do not assign Windows connection parameters to localhost. The Telegram token is selected in the following order: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_TOKEN`, `telegram_bot_token`, `telegram_token` (empty values are skipped); the recipient is `TELEGRAM_CHAT_ID` or `telegram_chat_id`. Ansible variables must be available to localhost. `run.sh` passes these environment variables to the EE. To use a separate HTTPS proxy for Telegram only, set `TELEGRAM_HTTPS_PROXY` or `telegram_https_proxy`; otherwise the regular EE environment is used. The bot must have permission to send messages to the specified chat. The final HTML report retains the original compact format: the "Updates completed" heading, host names, the "Installed/updated" section, and a list of file names without extra versions or explanations. Removal, warning, and error sections are displayed only when corresponding results exist; hosts with no changes or errors are omitted. A report is sent on every normal run, including runs with no changes (one shared "No changes." line) and planning or execution errors, before returning the final status. Long reports are split into parts; `unverified` means success based on the installer's return code rather than confirmation of the installed version. If configuration is missing, an explicit skip message is displayed. Telegram failure does not affect the final software management status; successful delivery or failure is reported without exposing the token. The report may contain host names, installer names, and diagnostic information: use a trusted chat and do not pass secrets in installer arguments. `--tags debug` enables safe, concise debug tasks alongside `always`; check mode disables Windows modifications and notification delivery.

## Windows state collection diagnostics

PowerShell scripts are passed via `script` using `lookup('ansible.builtin.file', ...)`, without requiring the `win_powershell` module to resolve their paths. Scripts must still be readable on the controller.

Software collection results are hidden by default. To diagnose only the initial state read, use:

```bash
./run.sh --limit test-host --check -e software_diagnostics=true -vv
```

Diagnostic output may contain details about installed software, paths, and uninstall commands. Do not publish it without reviewing it. Data masking for the other tasks is retained.

Indexing skips `.autodownload-stage` directories, `.aria2` files, and files with a corresponding adjacent `.aria2` sidecar. Source files are neither removed nor modified.

## Pattern contract

Merging of `patterns__all`, `patterns__<group>`, and `patterns__<hostname>` is retained. Patterns are merged by matching `id` or literally identical `regex`, even when their `id` values differ; if neither is specified, `name` is used. Priority: all → groups → host. Fields from the higher-priority pattern replace fields of the same name in the lower-priority pattern; the remaining fields are inherited. If an override does not specify `id`, the existing state key is retained; an explicitly specified new `id` replaces the previous one, and old state entries are not deleted automatically. Duplicates within a single list, conflicting patterns from different groups, and ambiguous matches by `id` and `regex` cause an error. Different regular expressions that match the same file are not treated as the same pattern.

Example pattern list item (not a complete inventory):

```yaml
- id: sample-app
  name: Sample App
  regex: 'sample-app-.*\.exe$'
  mode: exe
  state: present
  args: /S
  version_regex: '(\d+(?:\.\d+)+)'
  expected_return_code: [0, 3010]
  wait_for_children: true
  verify_signature: true
```

| Field | Semantics |
|---|---|
| `mode` | `exe`, `msi`, `arc`, `files` |
| `state` | `present` (default), `absent` |
| `id` | Stable product key; explicitly specifying it is recommended |
| `name` | Exact package DisplayName; not an arbitrary label when used as an identifier |
| `product_id` | Exact Uninstall registry key / MSI ProductCode, not a regex |
| `uninstall_name_regex` | Explicit DisplayName regex for safe uninstallation |
| `publisher` | Additional exact publisher filter |
| `creates_path` | Absolute path for an additional check during removal |
| `version_regex` | First capture group or full match; dates and integer versions require an explicit regex |
| `version_type` | `auto` (numbers with common alpha/beta/rc suffixes), `numeric`, `semver` (specify an exact regex for nonstandard prereleases) |
| `match_filename_only` | Matches the full path by default, as in the original implementation; `true` matches the basename |
| `args`, `uninstall_args` | String or list of strings; passed to win_package |
| `force` | Force the operation; defaults to false |
| `allow_downgrade`, `allow_unknown_version`, `reinstall_on_checksum_change` | Legacy parameters accepted for compatibility, but they do not change the new version and SHA-256 decision matrix |
| `pre`, `post` | A cmd.exe command or list of commands; PRE runs before every scheduled install, upgrade, removal or managed file update, POST after successful completion; errors prevent result confirmation |
| `dest`, `dest_subdir` | Destination directory and optional subdirectory for archives |
| `files` | For `files`, relative paths in `/source`; for `arc`, exact relative archive member names |
| `archive_layout` | `flat` by default for selective extraction, `tree` for the whole archive; collisions are prohibited |
| `template` | In `files`, Jinja2 rendering by default; `false` enables binary copying |
| `verify_signature` | Authenticode verification of the installer; defaults to false |
| `expected_return_code`, `wait_for_children` | win_package parameters |
| `reboot_policy` | Global parameter, `manual` or `end`; automatic reboot is disabled by default |

## Security and compatibility

- The entire plan is validated before modifying a host; general security and ordinary planning errors prevent changes to that host. Independent legacy-pattern errors are recorded separately and do not block other operations; the final status remains nonzero. Errors in individual execution operations are caught by `rescue`; independent operations continue. A failed run returns a nonzero final status if the final play is available.
- The artifact is selected by version together with its path and SHA-256. Equal versions with different contents and ambiguous unknown versions are blocked. SHA-256 verifies integrity between the controller and Windows, but does not establish trust in the original publisher. A separate signature verification mechanism is provided for that purpose.
- For `present` EXE/MSI/ARC, the controller makes its decision using a confirmed `state.json` entry, without comparing the installed program version in the registry. A successful installer result is not independent verification that the program actually exists. MSI identity is extracted locally from the package and retained for safe removal. Removal still requires actual identity verification; ambiguous products and interactive uninstallation without silent arguments are blocked.
- If no confirmed version/SHA-256 pair exists, installation is scheduled. If SHA-256 matches, the operation is skipped (a warning is added if the version differs). If SHA-256 differs, an upgrade is performed; a warning is added if the version matches. `force: true` retains the ability to force execution. The previous downgrade prohibition no longer applies: a different hash may correspond to an older package.
- EXE installers are launched via win_package without `product_id`/`creates_path` to prevent the module from skipping a scheduled operation. MSI packages use win_package; if it returns `changed=false`, a time-limited retry is made using standard msiexec with `REINSTALL=ALL REINSTALLMODE=vomus`. This is a standard mechanism for small MSI updates, but the rules of a particular MSI may prevent replacement of all files or a downgrade. Errors do not confirm state. Confirmation is based on the installer result and POST, not independent verification of the product version.
- Archive formats: ZIP, TAR, and compressed TAR variants supported by Python tarfile. RAR/7z and other formats are blocked; extending support requires a dedicated safe handler. Per-archive limits: 20,000 files and 8 GiB of extracted data. Symlinks, hardlinks, special files, directory traversal, and path collisions are prohibited. Empty directories are not transferred. For archives without `dest`/`dest_subdir`, a dedicated `name` directory is used, or a stable hash of the identifier if no name exists; older rules with different paths require an explicit `dest`.
- Extraction for each unique SHA-256 is performed once in a shared temporary controller cache. SHA-256 values, metadata, installer snapshots, and archive manifests are reused by all hosts during the run. No persistent cross-run cache is used. The source directory is indexed once. Installers are placed in `_src/<sha256>/`; after each successful state commit, the installer is queued for cleanup. At the end of host processing, a single call removes queued installers and their MSI logs, then prunes empty immediate subdirectories of `_src` named with 64 hexadecimal characters. Each queued installer is checked independently; failed operations are not queued. If processing is interrupted before cleanup, confirmed installers may remain in the cache. Nonempty directories, reparse points, `_src` itself, and the original `/source` are not deleted. Cleanup is not performed in check mode. Errors removing installers, empty cache directories, or temporary extracted files do not change the package processing result and are excluded from the final report and Telegram. Diagnostics remain in the Ansible log: individual cleanup failures produce warnings; a failed cleanup task is nonfatal. Installation and state write failures are still treated as errors.
- Windows directories are never recursively deleted: only explicitly listed files or manifest files are removed. An obsolete managed file whose checksum has changed blocks removal. Removing files inside the Windows system directory is prohibited. Changing the destination directory of an existing managed set requires a separate migration. Old markers are not migrated.
- The old version map is retained under `legacy` in the new `state.json` on the first state write, but is not treated as actual state. `state.json` is written via a temporary file and atomic replacement. The `pending`/`post` state is used to recheck and recover after a failure. Multi-file updates and installers are not transactional: some changes may already have occurred when a failure happens; the next run retries the incomplete operation or resumes POST from a successful saved receipt. PRE runs before every scheduled install, upgrade, removal (`state: absent`) or managed file/archive update (`update_files`), including first installs, forced operations and retries. POST runs after successful completion of these operations. On POST recovery only POST is resumed; PRE and the completed operation are not repeated. Neither hook runs for skips, state adoption/cleanup alone (`adopt`/`forget`), or check mode. A scheduled archive deployment (`update_files`) runs both hooks even if its individual file hashes already match. If PRE or the main operation fails, POST is not executed. The obsolete `pre_on_install` key is ignored for compatibility and can be removed from existing patterns. For simple `sc stop` commands, codes 1060 and 1062 are accepted; for `sc start`, code 1056 is accepted. Simple `taskkill /f /im <image>` commands (with these two options in either order) are executed via PowerShell by process name with `*` support: an absent process is a success without changes; access errors are not ignored. Complex commands, additional options, and commands with shell operators are executed as before via cmd.exe; only code 0 is accepted for them. State is updated only after successful execution and verification of the operation result.
- The `_state` and `_src` directories, application directories, and source files must not be writable by untrusted users. ACLs are not automatically changed. Reparse point checks reduce the risk but do not eliminate races if another process changes the filesystem between the check and the copy module. `flock` prevents concurrent execution through `run.sh` on a single controller; no distributed lock across multiple controllers exists. Checking expected database contents does not replace such a lock.
- Software collection covers system HKLM entries and HKCU entries of the WinRM account. Other user profiles and AppX/MSIX are not supported; EXE installation does not require an identifier. MSI packages installed in another user context are not considered reliably detected for the current context. `--check` builds the plan, checks paths/hashes, and renders templates, but does not simulate third-party installers.
- Templates are rendered on the controller and written in UTF-8 without BOM; any requirements for a different encoding or CRLF must be agreed separately. Previous template parameters and special `win_template` variables are not guaranteed. Do not expose results containing secrets from `no_log` tasks.

## Verification

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile library/software_manager.py module_utils/software_core.py
bash -n run.sh
ansible-playbook -i inventory.yaml playbook.yml --syntax-check
```

Run the verification commands in the target EE. Before production, run syntax-check, then check mode and verification on one test Windows host, including repeat runs and failure scenarios. Python tests verify controller logic and YAML contracts but do not replace integration testing of WinRM and Windows Installer.

Documentation: https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_locally.html ; https://docs.ansible.com/projects/ansible/latest/dev_guide/developing_module_utilities.html ; https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_package_module.html ; https://docs.ansible.com/projects/ansible/latest/collections/ansible/windows/win_powershell_module.html . The win_package and win_powershell contracts were verified against the official collection source code for version 3.2.0. The Windows Installer APIs were checked against Microsoft documentation: https://learn.microsoft.com/windows/win32/msi/installer-object ; https://learn.microsoft.com/windows/win32/msi/productversion ; https://learn.microsoft.com/windows/win32/msi/productstate .


## Compatibility with regex-only patterns

A unified state-based policy applies to all EXE/MSI packages with `state: present`. The `software_legacy_allow_unverified` parameter is no longer required. After a successful installer result and POST, `status: installer_reported` and `verification: installer_result` are saved; the report uses status `unverified`. This is an execution receipt, not confirmation that the application exists. Old `_installed` and `legacy` maps are not used as proof. Manual removal, self-updating, or corruption of an installed application is not detected through artifact state. On the first run without a complete state entry, the program may be installed again. A saved successful `post` stage allows only POST to be retried after a failure. For EXE/MSI installation or upgrade without POST, the intermediate `post` write is skipped: the installer result is verified and `done` is written. If interrupted between successful installer completion and writing `done`, `pending` remains and the next run may reinstall the package. For operations with POST, archives, files, and removal, the intermediate write is retained.

EXE removal using only an installer filename regex is prohibited. MSI removal without an explicit identifier is permitted only with an unambiguous previously saved MSI identity and actual Windows verification. For EXE/MSI rules with `state: absent`, a package with no matching installed identity, no active state record and no positive file probe is skipped silently (`no_removal_identity` if no identity is available). This does not prove that an unmanaged application is absent: specify `product_id`, `name` or `uninstall_name_regex` to detect it reliably. An active or pending state without a reliable identity, an existing probe without an uninstall identity, ambiguous matches and actual removal errors remain blocked. After verified removal using stored MSI metadata, `state.json` retains the MSI identity with `status: absent` so subsequent runs can detect reinstallation, including another ProductCode in the same UpgradeCode family. A confirmed absent package is skipped on subsequent runs; successful cleanup of a stale EXE/MSI state (`forget`) is not reported as a package change. For strict identification without changing inventory, pass a separate file using `-e @software-identities.yml`:

```yaml
software_identity_overrides:
  'example-.*\.msi':
    product_id: '{00000000-0000-0000-0000-000000000000}'
```

Replace the example with a real pattern key (id or regex) and the actual ProductCode, or specify an exact `name`/`uninstall_name_regex`. Allowed fields: `name`, `product_id`, `publisher`, `uninstall_name_regex`, `creates_path`, `uninstall_args`. They only fill in missing settings. Existing explicit identifiers are retained. Ambiguous matches are blocked. Independent errors involving legacy removal or missing or ambiguous artifacts appear in the final report without preventing other operations. Assigning the same installer to multiple patterns blocks the entire plan.


## Package installation and removal timeout

EXE/MSI operations via `win_package` are executed synchronously using the standard task keyword `timeout`. The Windows asynchronous wrapper is not used, so these tasks do not require creating a process via WMI. The default limit is 900 seconds. The global value can be specified without changing inventory:

```bash
./run.sh --limit test-host -e software_package_timeout=600
```

An optional `package_timeout: 1800` for an individual pattern overrides the global value. Integer values between 5 and 86400 seconds are accepted. Validation of package timeouts and relevant hook timeouts occurs in controller planning before batch transfer, PRE and state writes. Invalid package timeouts block only the affected operation. File hook timeouts are validated during manifest comparison after the actual action is known, including in check mode.

On timeout, the task fails; `rescue` records `status: error`, `timed_out: true`, and the reason in the report. POST, state confirmation, and installer cache deletion are not performed. State remains pending; other hosts and file operations continue. Remaining installation, removal, and POST recovery operations for packages on the same host run independently of the previous package failure, each with its own timeout. Automatic reboot of that host is deferred. The final playbook status remains nonzero. A timeout does not mean that the installation was cancelled or changes rolled back.

In Ansible Core 2.18.17, `timeout` limits action execution on the controller; exceeding it returns an error with the `timedout` field. This does not guarantee termination of a hung installer, child processes, or a separate Windows Installer service. No global termination of `msiexec.exe` or other processes is performed. For MSI code 1618, no more than two additional attempts are made at 15-second intervals; timeout applies to each attempt. When attempts are exhausted, the error is recorded only for the current package; subsequent packages execute normally, including their own retries for MSI 1618. An installer that timed out is not automatically restarted within the same operation. If the previous process remains active, subsequent installations may fail with MSI 1618 or time out. Automatic reboot is deferred only during the current run; before running again, verify that the previous installer and its child processes have terminated. Template preparation, other tasks, and error handling are outside the limit; connection closure and cleanup may also increase actual waiting time. The installer timeout limits `win_package` and MSI reapplication via `win_command`. Each PRE/POST command has a separate `software_hook_timeout` limit (120 seconds by default), which can be overridden in a pattern via `hook_timeout`. Range: 5–86400 seconds. PRE/POST timeout, like installer timeout, defers automatic reboot; it does not guarantee process termination. Copying and other tasks are not included in these limits. Check mode does not launch installers. Defender policies are not changed.

Patch verification: `python3 -m unittest discover -s tests -p test_package_timeout.py -v`. These are static YAML checks, not Windows execution tests.


## Current file logging

Operations are executed by numeric index in the existing `include_tasks`. `loop_control.label` and task names display `Index N/total`, the action, and the source filename (product name for removal). The number refers to the plan of a particular host, excluding products already skipped at planning. With `strategy: free`, output from different hosts can be interleaved; the existing initialization task name identifies the current package before a long installation. Separate informational debug tasks for launch, check mode, and timeout have been removed. The final report and errors remain; diagnostic tasks following set_fact run only with explicit `--tags debug` or `--tags never`, even when `always` is inherited. The final report remains enabled. In check mode, the decision is reflected in the task name and final report; Windows is not modified.

Binary files are transferred using one win_copy task per application; templates are written using the existing atomic operation, without a separate include_tasks for each file. Task names contain the artifact name or product identifier. loop_control.label contains the destination path; with no_log: true, the standard callback may hide individual item labels. Template contents, package arguments, and other sensitive data remain hidden. Neither -v nor --tags debug is required.

A separate task file for writing each individual file is no longer used.


## State-based planning and batch transfer

`state.json` remains on the target host; the controller reads it once, calculates SHA-256 and the version of source files, creates a plan, and prepares the data locally. Windows executes the plan, verifies transfer integrity, and atomically saves the new state. Installation and upgrade do not perform a separate registry scan before or after the installer. Mandatory safe detection of the installed product is retained for `absent`.

| State entry | Version | SHA-256 | Decision |
|---|---|---|---|
| No confirmed pair | — | — | install |
| Present | Matches | Matches | skip |
| Present | Differs | Matches | warning + skip |
| Present | Matches | Differs | warning + upgrade |
| Present | Differs | Differs | upgrade |

If a version cannot be identified, it is stored as JSON `null`. This is an accepted known uncertainty, not a missing field. Older entries support `version`/`checksum`; newer ones use `artifact_version`/`artifact_checksum`. The `pending` state requires a retry, except when a successful `post` stage has been saved for the same SHA-256, in which case POST is resumed. `force: true` overrides a skip. Warnings are included in the final report and do not make the run fail. When the hash matches but the version changes, only the artifact version fields (`version`, `artifact_version`, where applicable) are updated, without changing the confirmed installed product version, checksum, status, or identifiers, and without PRE/POST. All such entry updates are saved in one atomic operation before installation (except in check mode).

For MSI, the version is extracted locally using `msiinfo`; for EXE/ARC, it is taken from the filename using the existing regex. PE metadata is read locally and is not considered a reliable installed program version. Selection of the highest available version from multiple candidates is retained; ambiguous matches are blocked. Unlike the previous policy, an older source package with a different SHA-256 will also be scheduled. If an application is manually removed or its version changes outside Ansible, a matching artifact is skipped; use `force: true` to reapply it. Changing archive pattern settings without changing the artifact also requires `force: true`. The unversioned `files` mode retains comparison of actual managed files and controller-side template rendering.

Before executing the plan, the controller creates a temporary `_src` tree containing only install/upgrade packages. A copy of each unique SHA-256 is created once on the controller; individual host trees use hard links to that verified copy. One win_copy task transfers the tree over WinRM. In ansible.windows 3.2.0, the action plugin automatically uses ZIP when transferring multiple files/directories. If shared preparation, path validation, or transfer fails, the previous per-installer preparation attempt is retained. Each installation has an individual timeout, security checks, and independent error handling. The cache does not contain the original inventory and is cleaned in the final play. Failed installers remain in `_src` on Windows.

ARC uses a shared extracted cache on the controller keyed by SHA-256. Modified binary files of one application form a temporary tree with relative paths and are transferred in a single win_copy call. Target files are checked before and after changes; comparison of the entire manifest and the final decision are performed by the local Python module without per-file set_fact/assert loops. Unrelated files are not removed. Templates retain the existing atomic write mechanism. In check mode, batch transfer, installations, and state writes are not performed. Consecutive managed-file operations share one read-only Windows inspection of their paths; a path inspection error is attributed to the affected product. The snapshot is discarded after an operation that does not skip or after an error, so subsequent operations see changes made by preceding installers and hooks. Templates are still rendered for each product. Before execution, the initial consecutive file operations are inspected as a batch, template checksums are rendered on the controller, and the controller excludes the confirmed unchanged prefix. No execution task file is included for those products. The first non-skip operation and all subsequent operations retain normal execution-time checks, because an installer or a hook may change later files. If preflight fails, individual checks are used instead. The controller combines final verification and preparation of the next state database; Windows commits that database using the existing atomic expected-content check. Pending and required POST checkpoints remain durable. Removal without POST commands and without a reboot requirement does not require a separate POST checkpoint: recovery still checks whether the product is absent. Removal with POST or a reboot requirement and file updates keep their checkpoint.

If MSI win_package returns `changed=false`, a separate `msiexec /i ... /qn /norestart REINSTALL=ALL REINSTALLMODE=vomus` attempt is made with the specified arguments, log, and timeout. This standard small-update mechanism does not guarantee replacement of all same-version files or success with a nonstandard MSI; an MSI may reject a downgrade. Code 1618 still receives limited retries. There is no automatic disabling of Defender and no additional package managers.

Documentation: https://github.com/ansible-collections/ansible.windows/blob/3.2.0/plugins/action/win_copy.py ; https://learn.microsoft.com/windows/win32/msi/applying-small-updates-by-reinstalling-the-product ; https://manpages.debian.org/trixie/msitools/msiinfo.1.en.html .


### Updating rules for new installer filenames

Replace existing rules rather than adding duplicates. When changing a regex, retain the previous identifier via `id` if the link to the state entry must be preserved; use the same id for group/host overrides. Do not change `state` or other individual settings unnecessarily.

```yaml
- { regex: "aimp.+\\.exe", mode: exe, args: '/AUTO="C:\Users\{{ ansible_user }}\Desktop\AIMP" /SILENT', pre: ["taskkill /im aimp* /f"] }
- { id: 'blender-[\d\.]-windows-x64\.msi', regex: '^blender-[\d.]+-windows-x64\.msi$', mode: msi, args: ["/quiet", "/norestart"] }
- { id: 'inkscape-.+-x64.exe', regex: '^inkscape-.+-x64(?:\.signed)?\.exe$', version_regex: '^inkscape-([\d.]+)', mode: exe, args: '/S /D=C:\Program Files\Inkscape', pre: ['if exist "C:\Program Files\Inkscape\Uninstall.exe" ("C:\Program Files\Inkscape\Uninstall.exe" /S) else (exit /b 0)'] }
```

The AIMP `/AUTO` and `/SILENT` parameters are documented by the developer. For Mumble `mumble_client-1.5.939.x64.exe`, `mode: exe`, regex `^mumble_client-[\d.]+\.x64\.exe$`, and verified arguments for this specific EXE are required. Retain id `mumble_client-[\d.]+.x64.msi` when changing the previous pattern. Do not launch an unverified EXE without silent installation arguments. Host configuration files are not modified by this patch.

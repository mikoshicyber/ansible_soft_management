import fcntl
import hashlib
import json
import ntpath
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path


class SoftwareError(ValueError):
    pass


def digest(stream, limit=None):
    h = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        size += len(chunk)
        if limit is not None and size > limit:
            raise SoftwareError('Archive member exceeds declared size')
        h.update(chunk)
    return h.hexdigest()


def sha(path):
    with open(path, 'rb') as stream:
        return digest(stream)


def relative(value):
    if not isinstance(value, str) or not value:
        raise SoftwareError('Empty or invalid relative path')
    parts = value.replace('\\', '/').split('/')
    if any(not p or p in ('.', '..') or p[-1] in ' .' or re.search(r'[<>:"|?*\x00-\x1f]', p)
           or re.match(r'(?i)^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)', p) for p in parts):
        raise SoftwareError('Unsafe relative path: ' + value)
    return '/'.join(parts)


def winroot(value):
    if not isinstance(value, str) or not re.match(r'^[A-Za-z]:[\\/]', value):
        raise SoftwareError('Expected an absolute local Windows path')
    tail = value[3:].rstrip('\\/')
    if not tail:
        raise SoftwareError('Drive root is not a managed directory')
    return value[:2].upper() + '\\' + relative(tail).replace('/', '\\')


def target(root, rel):
    return winroot(root) + '\\' + relative(rel).replace('/', '\\')


def inside(path, root):
    p, r = ntpath.normcase(path), ntpath.normcase(root)
    return p.startswith(r + '\\')


def boolean(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ('true', 'false'):
        return value.lower() == 'true'
    raise SoftwareError('Expected a boolean')


def commands(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value):
        raise SoftwareError('Expected a command string or list of strings')
    return value



def hook_commands(values):
    result = []
    for command in values:
        hook = {'command': command, 'kind': 'command', 'accepted_rc': [0]}
        service = re.fullmatch(r'\s*sc(?:\.exe)?\s+(stop|start)\s+(?:"[A-Za-z0-9_. -]+"|[A-Za-z0-9_.-]+)\s*', command, re.I)
        process = re.fullmatch(r'\s*taskkill(?:\.exe)?\s+(?:/f\s+/im\s+(?P<first>"[A-Za-z0-9_. *-]+"|[A-Za-z0-9_.*-]+)|/im\s+(?P<last>"[A-Za-z0-9_. *-]+"|[A-Za-z0-9_.*-]+)\s+/f)\s*', command, re.I)
        if service:
            hook.update(kind='service', accepted_rc=[0, 1060, 1062] if service[1].lower() == 'stop' else [0, 1056])
        elif process:
            image = (process['first'] or process['last']).strip('"')
            if image.lower() not in ('*', '*.exe', '*.*') and re.search(r'[A-Za-z0-9_-]', image.lower().removesuffix('.exe')):
                hook.update(kind='process', image=image)
        result.append(hook)
    return result


def msi_arguments(value):
    if isinstance(value, str):
        return value
    args = []
    for arg in value:
        if arg.lower() in ('/quiet', '/qn', '/norestart'):
            continue
        prop = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)=(.*)', arg)
        if prop:
            name, data = prop.groups()
            if len(data) >= 2 and data.startswith('"') and data.endswith('"'):
                args.append(arg)
            elif any(ch.isspace() for ch in data):
                args.append(name + '="' + data.replace('"', '""') + '"')
            else:
                args.append(arg)
        else:
            args.append(subprocess.list2cmdline([arg]))
    return ' '.join(args)


def merge(layers, dest, identity_overrides=None):
    dest = winroot(dest)
    out = []
    group_values = {}
    priority = {'all': 0, 'group': 1, 'host': 2}
    for layer in sorted(layers, key=lambda item: priority.get(item.get('scope'), 0)):
        entries = layer.get('patterns') or []
        if not isinstance(entries, list):
            raise SoftwareError('patterns__* must be a list')
        seen = set()
        seen_keys = set()
        seen_regex = set()
        for raw in entries:
            if not isinstance(raw, dict):
                raise SoftwareError('Pattern must be a mapping')
            key = raw.get('id') or raw.get('regex') or raw.get('name')
            if not isinstance(key, str) or not key:
                raise SoftwareError('Pattern requires id, regex or name')
            regex = raw.get('regex')
            if regex is not None and (not isinstance(regex, str) or not regex):
                raise SoftwareError('Invalid regex: ' + key)
            if key in seen_keys or (regex is not None and regex in seen_regex):
                raise SoftwareError('Duplicate pattern: ' + key)
            seen_keys.add(key)
            if regex is not None:
                seen_regex.add(regex)
            matches = [index for index, pattern in enumerate(out)
                       if pattern['id'] == key or (regex is not None and pattern.get('regex') == regex)]
            if len(matches) > 1:
                raise SoftwareError('Conflicting pattern id and regex: ' + key)
            index = matches[0] if matches else len(out)
            if index in seen:
                raise SoftwareError('Duplicate pattern: ' + key)
            seen.add(index)
            if layer.get('scope') == 'group':
                if index in group_values and group_values[index] != raw:
                    raise SoftwareError('Conflicting group patterns: ' + key)
                group_values[index] = raw
            previous = out[index] if matches else {}
            merged = dict(previous, **raw)
            merged['id'] = raw.get('id') or previous.get('id') or key
            if matches:
                out[index] = merged
            else:
                out.append(merged)
    identity_overrides = {} if identity_overrides is None else identity_overrides
    if not isinstance(identity_overrides, dict):
        raise SoftwareError('software_identity_overrides must be a mapping')
    for key, fields in identity_overrides.items():
        if not isinstance(fields, dict) or set(fields) - {'name', 'product_id', 'publisher', 'uninstall_name_regex', 'creates_path', 'uninstall_args'}:
            raise SoftwareError('Invalid identity override: ' + str(key))
    result = []
    for p in out:
        key = p['id']
        for field, value in identity_overrides.get(key, {}).items():
            p.setdefault(field, value)
        p['id'] = key
        p['mode'] = p.get('mode', 'exe')
        p['state'] = p.get('state', 'present')
        if p['mode'] not in ('exe', 'msi', 'arc', 'files') or p['state'] not in ('present', 'absent'):
            raise SoftwareError('Invalid mode/state: ' + key)
        for field in ('name', 'product_id', 'publisher', 'creates_path', 'dest_subdir'):
            if field in p and (not isinstance(p[field], str) or not p[field].strip()):
                raise SoftwareError('Invalid ' + field + ': ' + key)
        for field in ('regex', 'version_regex', 'uninstall_name_regex'):
            if field in p:
                if not isinstance(p[field], str) or not p[field]:
                    raise SoftwareError('Invalid regex: ' + key)
                re.compile(p[field], re.I)
        for field, default in [('force', False), ('allow_downgrade', False), ('allow_unknown_version', False),
                               ('wait_for_children', True), ('template', True), ('verify_signature', False), ('match_filename_only', False), ('reinstall_on_checksum_change', False)]:
            p[field] = boolean(p.get(field, default))
        p.pop('pre_on_install', None)
        for field in ('pre', 'post', 'files'):
            p[field] = commands(p.get(field, []))
        for field in ('pre', 'post'):
            p[field + '_commands'] = hook_commands(p[field])
        p['files'] = [relative(x) for x in p['files']]
        for field in ('args', 'uninstall_args'):
            if field in p and not isinstance(p[field], str):
                p[field] = commands(p[field])
        if p['mode'] == 'msi':
            for field in ('args', 'uninstall_args'):
                if field in p:
                    p[field] = msi_arguments(p[field])
        p['expected_return_code'] = p.get('expected_return_code', [0, 3010])
        if not isinstance(p['expected_return_code'], list) or not p['expected_return_code'] or any(type(x) is not int for x in p['expected_return_code']):
            raise SoftwareError('expected_return_code must be a nonempty integer list')
        if p.get('creates_path'):
            p['creates_path'] = winroot(p['creates_path'])
        if p['mode'] == 'files' and not p['files']:
            raise SoftwareError('files mode requires explicit files: ' + key)
        if p['mode'] != 'files' and p['state'] == 'present' and not p.get('regex'):
            raise SoftwareError('Missing artifact regex: ' + key)
        p['root'] = winroot(p.get('dest', dest))
        if p['mode'] == 'arc' and p.get('dest_subdir'):
            p['root'] = target(p['root'], p['dest_subdir'])
        elif p['mode'] == 'arc' and 'dest' not in p:
            name = p.get('name')
            if not name:
                name = 'app-' + hashlib.sha256(key.encode()).hexdigest()[:16]
            p['root'] = target(dest, name)
        for reserved in (target(dest, '_src'), target(dest, '_state')):
            if p['root'].lower() == reserved.lower() or inside(p['root'], reserved):
                raise SoftwareError('Reserved destination: ' + key)
        p['archive_layout'] = p.get('archive_layout', 'flat' if p['files'] else 'tree')
        if p['archive_layout'] not in ('flat', 'tree'):
            raise SoftwareError('Invalid archive_layout')
        p['version_type'] = p.get('version_type', 'auto')
        if p['version_type'] not in ('auto', 'numeric', 'semver'):
            raise SoftwareError('Unsupported version_type')
        result.append(p)
    return result


def version_key(value, kind='auto'):
    if not value:
        return None
    text = str(value).strip().lower().lstrip('v')
    if kind == 'semver':
        m = re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9a-z.-]+))?(?:\+[0-9a-z.-]+)?', text)
        if not m:
            return None
        pre = m[4].split('.') if m[4] else []
        if any(not x or (x.isdigit() and len(x) > 1 and x.startswith('0')) for x in pre):
            return None
        return tuple(int(m[i]) for i in (1, 2, 3)), 0 if pre else 1, tuple((0, int(x)) if x.isdigit() else (1, x) for x in pre)
    m = re.fullmatch(r'(\d+(?:[._]\d+)*)(?:[-.]?(alpha|beta|a|b|rc|pre|preview)(?:[.-]?(\d+))?)?(?:\+[0-9a-z.-]+)?', text)
    if not m or (kind == 'numeric' and m[2]):
        return None
    nums = [int(n) for n in re.split(r'[._]', m[1])]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    rank = {None: 3, 'alpha': 0, 'a': 0, 'beta': 1, 'b': 1, 'rc': 2, 'pre': 2, 'preview': 2}[m[2]]
    return tuple(nums), rank, int(m[3] or 0)


def parse_version(name, p):
    if 'version_regex' not in p:
        name = re.sub(r'(?<![a-z0-9])(?:x86[_-]64|x86|x64|amd64|arm64|aarch64|i[3-6]86|win32|win64)(?![a-z0-9])', ' ', name, flags=re.I)
    default_regex = r'(?<!\d)\d+(?:[._]\d+)+(?:[-.]?(?:alpha|beta|rc|pre)(?:[.-]?\d+)?)?'
    m = re.search(p.get('version_regex', default_regex), name, re.I)
    if not m:
        return None
    value = m.group(1) if m.lastindex else m.group(0)
    return value if version_key(value, p['version_type']) is not None else None


def index(source):
    root = Path(source).resolve(strict=True)
    if not root.is_dir():
        raise SoftwareError('Source is not a directory')
    paths = []
    def fail(exc):
        raise exc
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        dirs[:] = sorted(d for d in dirs if d != '.autodownload-stage' and not (Path(directory) / d).is_symlink())
        filenames = set(files)
        for f in sorted(files):
            if f.endswith('.aria2') or f + '.aria2' in filenames:
                continue
            path = Path(directory) / f
            if path.is_file() and not path.is_symlink():
                paths.append(str(path))
    return paths


def source_file(source, path):
    root = Path(source).resolve(strict=True)
    original = Path(path)
    resolved = original.resolve(strict=True)
    if original != resolved or root not in resolved.parents or not resolved.is_file():
        raise SoftwareError('Source path is outside the catalog or is a link')
    return str(resolved)


def cached_sha(path, cache_dir=None):
    if not cache_dir:
        return sha(path)
    before = os.stat(path)
    fingerprint = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    key = hashlib.sha256(repr(fingerprint).encode()).hexdigest()
    entry = Path(cache_dir) / ('sha-' + key)
    with open(str(entry) + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if entry.exists():
            value = entry.read_text()
            if re.fullmatch(r'[0-9a-f]{64}', value):
                now = os.stat(path)
                if fingerprint == (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns):
                    return value
                raise SoftwareError('Artifact changed while accessing SHA-256 cache')
        value = sha(path)
        after = os.stat(path)
        if fingerprint != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise SoftwareError('Artifact changed while calculating SHA-256')
        entry.write_text(value)
        return value


def matching_paths(p, catalog):
    return [path for path in catalog
            if re.search(p['regex'], os.path.basename(path) if p.get('match_filename_only', False) else path, re.I)
            and (p['mode'] not in ('exe', 'msi') or path.lower().endswith('.' + p['mode']))]


def guid(value):
    return isinstance(value, str) and re.fullmatch(r'\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}', value) is not None


def valid_msi_metadata(value):
    return (isinstance(value, dict) and guid(value.get('product_id'))
            and (not value.get('upgrade_code') or guid(value['upgrade_code']))
            and isinstance(value.get('version'), str)
            and msi_version(value['version']) is not None
            and all(isinstance(value.get(field, ''), str) for field in ('name', 'publisher', 'language', 'platform')))


def msi_version(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+(?:\.\d+){0,3}', value):
        return None
    return tuple((list(map(int, value.split('.'))) + [0, 0, 0])[:3])


def check_metadata_tools():
    if not shutil.which('msiinfo'):
        raise SoftwareError('msiinfo not found; build the metadata Execution Environment using Dockerfile')
    try:
        import pefile
    except ImportError as exc:
        raise SoftwareError('pefile not found in Ansible Python; build the metadata Execution Environment using Dockerfile') from exc


def msiinfo(path, *args):
    try:
        result = subprocess.run(['msiinfo', args[0], path, *args[1:]],
                                capture_output=True, text=True, encoding='utf-8',
                                timeout=60, check=True,
                                env=dict(os.environ, LC_ALL='C.UTF-8'))
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise SoftwareError('msiinfo ' + args[0] + ' failed for ' + os.path.basename(path)) from exc
    return result.stdout


def read_msi_metadata(path):
    rows = msiinfo(path, 'export', 'Property').splitlines()
    if len(rows) < 3 or rows[0].split('\t') != ['Property', 'Value']:
        raise SoftwareError('Invalid MSI Property table: ' + os.path.basename(path))
    properties = {}
    for row in rows[3:]:
        key, sep, value = row.partition('\t')
        if sep:
            if key in properties:
                raise SoftwareError('Duplicate MSI property: ' + key)
            properties[key] = value
    summary = msiinfo(path, 'suminfo')
    template = re.search(r'^Template:[ \t]*([^\r\n]*)$', summary, re.M)
    if not template:
        raise SoftwareError('MSI platform unavailable: ' + os.path.basename(path))
    platform = template.group(1).split(';', 1)[0].strip() or 'Intel'
    result = {key: properties.get(field, '') for key, field in (
        ('product_id', 'ProductCode'), ('upgrade_code', 'UpgradeCode'),
        ('version', 'ProductVersion'), ('name', 'ProductName'),
        ('publisher', 'Manufacturer'), ('language', 'ProductLanguage'))}
    result['platform'] = platform
    if not valid_msi_metadata(result):
        raise SoftwareError('Invalid MSI metadata: ' + os.path.basename(path))
    return result


def read_exe_metadata(path):
    import pefile
    pe = None
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        fields = {b'ProductName': 'name', b'CompanyName': 'publisher',
                  b'ProductVersion': 'product_version', b'FileVersion': 'file_version'}
        values = {field: set() for field in fields.values()}
        for group in getattr(pe, 'FileInfo', []) or []:
            for entry in group if isinstance(group, (list, tuple)) else [group]:
                for table in getattr(entry, 'StringTable', []):
                    for raw_key, raw_value in table.entries.items():
                        key = raw_key if isinstance(raw_key, bytes) else raw_key.encode('utf-8')
                        if key in fields:
                            value = raw_value.decode('utf-8', errors='replace') if isinstance(raw_value, bytes) else str(raw_value)
                            value = value.strip('\x00 \t\r\n')
                            if value and '\ufffd' not in value:
                                values[fields[key]].add(value)
        result = {key: next(iter(items)) for key, items in values.items() if len(items) == 1}
        result['machine'] = int(pe.FILE_HEADER.Machine)
        return result
    except (OSError, ValueError, pefile.PEFormatError):
        return {}
    finally:
        if pe is not None:
            pe.close()


def local_metadata(path, checksum, kind, cache_dir=None):
    reader = read_msi_metadata if kind == 'msi' else read_exe_metadata
    if not re.fullmatch(r'[0-9a-f]{64}', checksum):
        raise SoftwareError('Invalid artifact checksum')
    if not cache_dir:
        return reader(path)
    entry = Path(cache_dir) / ('local-' + kind + '-' + checksum + '.json')
    with open(str(entry) + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if cached_sha(path, cache_dir) != checksum:
            raise SoftwareError('Artifact changed before metadata reading')
        if entry.is_file():
            return json.loads(entry.read_text())
        result = reader(path)
        if cached_sha(path, cache_dir) != checksum:
            raise SoftwareError('Artifact changed during metadata reading')
        with tempfile.NamedTemporaryFile(mode='w', dir=cache_dir, delete=False) as temp:
            name = temp.name
            json.dump(result, temp)
        try:
            os.replace(name, entry)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return result


def discover_msi(patterns, catalog, source, db, cache_dir=None):
    metadata, identities, errors = {}, {}, {}
    for p in patterns:
        if p['mode'] != 'msi':
            continue
        old = db['products'].get(p['id'], {})
        if p['state'] != 'present':
            if valid_msi_metadata(old.get('msi_metadata')):
                identities[p['id'] + ':stored'] = old['msi_metadata']
            if p.get('product_id') and guid(p['product_id']):
                identities[p['id']] = {'product_id': p['product_id']}
            continue
        for path in matching_paths(p, catalog):
            checksum = None
            try:
                filename = source_file(source, path)
                checksum = cached_sha(filename, cache_dir)
                if checksum not in metadata and checksum not in errors:
                    metadata[checksum] = local_metadata(filename, checksum, 'msi', cache_dir)
            except (ValueError, OSError) as exc:
                errors[checksum or path] = str(exc)
    return {'metadata': metadata, 'identities': identities, 'errors': errors}


def select_artifact(p, catalog, source, metadata=None, cache_dir=None, metadata_errors=None):
    matches = []
    for path in matching_paths(p, catalog):
        version = parse_version(os.path.basename(path), p)
        checksum = None
        meta = None
        if p['mode'] == 'msi' and metadata is not None:
            checksum = cached_sha(source_file(source, path), cache_dir)
            meta = metadata.get(checksum)
            if not valid_msi_metadata(meta):
                reason = (metadata_errors or {}).get(checksum) or (metadata_errors or {}).get(path)
                raise SoftwareError('MSI metadata unavailable: ' + os.path.basename(path) + (': ' + reason if reason else '; review controller metadata read errors'))
            if 'version_regex' not in p:
                version = meta['version']
            elif version is None:
                raise SoftwareError('Explicit version_regex did not match MSI: ' + os.path.basename(path))
        rank = msi_version(version) if meta and 'version_regex' not in p else version_key(version, p['version_type'])
        matches.append((rank, version, path, checksum, meta))
    if not matches:
        raise SoftwareError('No matching artifact')
    if len(matches) > 1 and any(x[0] is None for x in matches):
        raise SoftwareError('Multiple artifacts with unknown versions')
    if metadata is not None and p['mode'] == 'msi' and len(matches) > 1:
        families = {((x[4].get('upgrade_code') or x[4]['product_id']).casefold(),
                     (x[4].get('language') or ''), (x[4].get('platform') or '').casefold()) for x in matches}
        if len(families) != 1:
            raise SoftwareError('MSI candidates belong to different product families, languages or architectures')
    best = max((x[0] for x in matches if x[0] is not None), default=None)
    chosen = [x for x in matches if x[0] == best]
    paths = [(x, x[3] or cached_sha(source_file(source, x[2]), cache_dir)) for x in chosen]
    if len({x[1] for x in paths}) != 1:
        raise SoftwareError('Different artifacts with identical version')
    x, checksum = sorted(paths, key=lambda x: x[0][2])[0]
    artifact = {'source': x[2], 'filename': os.path.basename(x[2]), 'version': x[1], 'checksum': checksum}
    if x[4]:
        artifact['msi_metadata'] = x[4]
    elif p['mode'] == 'exe' and cache_dir:
        try:
            artifact['exe_metadata'] = local_metadata(source_file(source, x[2]), checksum, 'exe', cache_dir)
        except ImportError:
            artifact['exe_metadata'] = {}
    return artifact


def archive_members(path, max_bytes=8 * 1024**3, max_files=20000, extract_to=None):
    files = []
    seen = set()
    parent_paths = set()
    total = 0
    def member(name, size, stream):
        nonlocal total
        rel = relative(name)
        lower = rel.casefold()
        parents = {'/'.join(lower.split('/')[:i]) for i in range(1, len(lower.split('/')))}
        if lower in seen or lower in parent_paths or parents & seen:
            raise SoftwareError('Archive contains colliding paths')
        seen.add(lower)
        parent_paths.update(parents)
        total += size
        if len(seen) > max_files or total > max_bytes:
            raise SoftwareError('Archive exceeds configured limits')
        with stream:
            if extract_to:
                output = Path(extract_to) / rel
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open('xb') as dst:
                    h = hashlib.sha256()
                    count = 0
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        count += len(chunk)
                        if count > size:
                            raise SoftwareError('Invalid member size')
                        h.update(chunk)
                        dst.write(chunk)
                    if count != size:
                        raise SoftwareError('Truncated archive member')
                    checksum = h.hexdigest()
            else:
                checksum = digest(stream, size)
        files.append({'relative': rel, 'checksum': checksum})
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as arc:
            for info in arc.infolist():
                mode = info.external_attr >> 16
                if info.flag_bits & 1 or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise SoftwareError('Encrypted or special ZIP entry')
                if info.is_dir():
                    relative(info.filename.rstrip('/'))
                    continue
                member(info.filename, info.file_size, arc.open(info))
    elif tarfile.is_tarfile(path):
        with tarfile.open(path, 'r:*') as arc:
            for info in arc:
                if info.isdir():
                    if info.name.rstrip('/') not in ('.', ''):
                        relative(info.name.rstrip('/'))
                    continue
                if not info.isfile() or info.issparse():
                    raise SoftwareError('Archive contains link or special entry')
                name = info.name[2:] if info.name.startswith('./') else info.name
                member(name, info.size, arc.extractfile(info))
    else:
        raise SoftwareError('Unsupported archive: only ZIP and TAR variants are supported')
    if not files:
        raise SoftwareError('Empty archive')
    return files


def normalize_state(raw):
    data = json.loads(raw) if isinstance(raw, str) else raw
    if not isinstance(data, dict):
        raise SoftwareError('Invalid state database')
    if 'schema_version' not in data:
        if not all(isinstance(v, str) for v in data.values()):
            raise SoftwareError('Unknown legacy state')
        return {'schema_version': 2, 'products': {}, 'legacy': data}
    if data['schema_version'] != 2 or not isinstance(data.get('products'), dict):
        raise SoftwareError('Unsupported state schema')
    meta_cache = data.get('msi_metadata_cache', {})
    if not isinstance(meta_cache, dict) or any(not re.fullmatch(r'[0-9a-f]{64}', k) or not valid_msi_metadata(v) for k, v in meta_cache.items()):
        raise SoftwareError('Invalid MSI metadata cache')
    for key, value in data['products'].items():
        if not isinstance(key, str) or not isinstance(value, dict) or not isinstance(value.get('files', []), list):
            raise SoftwareError('Invalid product state')
        if 'identity' in value and (not isinstance(value['identity'], dict) or any(not isinstance(v, str) for v in value['identity'].values())):
            raise SoftwareError('Invalid stored product identity')
        for field in ('msi_metadata', 'pending_msi_metadata'):
            if field in value and not valid_msi_metadata(value[field]):
                raise SoftwareError('Invalid stored MSI metadata')
        for f in value.get('files', []):
            if not isinstance(f, dict) or not isinstance(f.get('path'), str) or not re.fullmatch(r'[0-9a-f]{64}', f.get('checksum', '')):
                raise SoftwareError('Invalid stored file manifest')
            if winroot(f['path']) != f['path']:
                raise SoftwareError('Noncanonical stored file path')
    return data


def find_installed(p, installed):
    matched = []
    exact = []
    for app in installed:
        if p.get('publisher') and (app.get('publisher') or '').casefold() != p['publisher'].casefold():
            continue
        identity = bool(p.get('product_id') and (app.get('product_id') or '').casefold() == p['product_id'].casefold())
        if identity:
            exact.append(app)
        if p.get('uninstall_name_regex'):
            identity = identity or bool(re.search(p['uninstall_name_regex'], app.get('name') or '', re.I))
        elif p.get('name'):
            identity = identity or (app.get('name') or '').casefold() == p['name'].casefold()
        if identity:
            matched.append(app)
    if exact:
        matched = exact
    if len(matched) > 1:
        raise SoftwareError('Ambiguous installed product')
    return matched[0] if matched else None


def learned_app(old, installed):
    identity = old.get('identity') or {}
    if not identity.get('registry_key') or not identity.get('name') or not identity.get('publisher'):
        return None
    def matches(app):
        return all((app.get(field) or '').casefold() == identity[field].casefold()
                   for field in ('name', 'publisher')) and (not identity.get('provider') or identity['provider'] == app.get('provider'))
    exact = [app for app in installed if matches(app) and (app.get('registry_key') or '').casefold() == identity['registry_key'].casefold()]
    candidates = exact or [app for app in installed if matches(app)]
    if len(candidates) > 1:
        raise SoftwareError('Ambiguous learned product identity')
    return candidates[0] if candidates else None


def msi_app(meta, snapshot):
    related = snapshot.get('msi_related', {})
    code = meta['product_id'].casefold()
    family = (meta.get('upgrade_code') or '').casefold()
    if family and family not in related:
        raise SoftwareError('MSI UpgradeCode was not inspected')
    codes = {code} | {str(x).casefold() for x in related.get(family, [])}
    states = snapshot.get('msi_states', {})
    if any(states.get(c) not in (-1, 1, 5) for c in codes):
        raise SoftwareError('MSI product state unavailable, corrupt or installed for a different user')
    candidates = [app for app in snapshot['installed'] if app.get('provider') == 'msi' and (app.get('product_id') or '').casefold() in codes and states.get((app.get('product_id') or '').casefold()) == 5]
    if any(states.get(c) == 5 and not any((a.get('product_id') or '').casefold() == c for a in candidates) for c in codes):
        raise SoftwareError('MSI product version could not be read')
    if len(candidates) > 1:
        raise SoftwareError('Multiple installed products share MSI identity; explicit disambiguation required')
    if candidates:
        app = candidates[0]
        for field in ('language', 'platform'):
            if meta.get(field) and app.get(field) and str(meta[field]).casefold() != str(app[field]).casefold():
                raise SoftwareError('Installed MSI differs from target ' + field + '; explicit disambiguation required')
        return app
    return None


def package_app(op, snapshot):
    p = op['pattern']
    meta = op.get('artifact', {}).get('msi_metadata') or op.get('msi_identity')
    if meta:
        app = msi_app(meta, snapshot)
        if op['pattern']['state'] == 'present' and any(p.get(x) for x in ('product_id', 'name', 'uninstall_name_regex')):
            explicit = find_installed(p, snapshot['installed'])
            if explicit and (not app or explicit.get('product_id', '').casefold() != app.get('product_id', '').casefold()):
                raise SoftwareError('Explicit identity conflicts with the MSI product family')
        return app
    if op.get('learned_identity'):
        return learned_app({'identity': op['learned_identity']}, snapshot['installed'])
    return find_installed(p, snapshot['installed'])


def compare_package_version(value, op):
    if op.get('artifact', {}).get('msi_metadata') or op.get('msi_identity'):
        return msi_version(value)
    return version_key(value, op['pattern']['version_type'])


def identity_record(app):
    if not app or not all(app.get(x) for x in ('registry_key', 'name', 'publisher', 'product_id')):
        return None
    return {x: app[x] for x in ('registry_key', 'name', 'publisher', 'product_id', 'provider') if x in app}


def learn_from_change(before, after, hints):
    if not hints.get('name') or not hints.get('publisher'):
        return None
    def key(app):
        return (app.get('registry_key') or '').casefold()
    prior = {key(app): app for app in before if key(app)}
    changed = [app for app in after if key(app) and identity_record(app)
               and (key(app) not in prior or prior[key(app)].get('version') != app.get('version'))]
    matches = [app for app in changed if app['name'].casefold() == hints['name'].casefold()
               and app['publisher'].casefold() == hints['publisher'].casefold()]
    return matches[0] if len(matches) == 1 else None


def file_manifest(p, artifact, source, cache_dir=None):
    if p['mode'] == 'files':
        files = []
        for rel in p['files']:
            src = source_file(source, str(Path(source).resolve() / rel))
            files.append({'relative': rel, 'path': target(p['root'], rel), 'source': src, 'checksum': cached_sha(src, cache_dir)})
        return files
    if cache_dir:
        entry = Path(cache_dir) / ('manifest-' + artifact['checksum'] + '.json')
        with open(str(entry) + '.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if entry.exists():
                members = json.loads(entry.read_text())
            else:
                members = archive_members(artifact['source'])
                if sha(artifact['source']) != artifact['checksum']:
                    raise SoftwareError('Archive changed while reading manifest')
                entry.write_text(json.dumps(members))
    else:
        members = archive_members(artifact['source'])
    if p['files']:
        wanted = set(p['files'])
        members = [m for m in members if m['relative'] in wanted]
        if {m['relative'] for m in members} != wanted:
            raise SoftwareError('Requested archive members not found')
    for m in members:
        rel = os.path.basename(m['relative']) if p['archive_layout'] == 'flat' else m['relative']
        m['path'] = target(p['root'], rel)
    if len({m['path'].casefold() for m in members}) != len(members):
        raise SoftwareError('Archive destination collision')
    return members


def state_artifact_action(op):
    p, old, artifact = op['pattern'], op['old'], op['artifact']
    checksum, version = artifact['checksum'], artifact['version']
    old_checksum = old.get('artifact_checksum', old.get('checksum'))
    has_version = 'artifact_version' in old or 'version' in old
    old_version = old.get('artifact_version', old.get('version'))
    complete = (old.get('status') in ('installed', 'installer_reported')
                and isinstance(old_checksum, str) and re.fullmatch(r'[0-9a-fA-F]{64}', old_checksum)
                and has_version and (old_version is None or (isinstance(old_version, str) and old_version.strip())))
    if (old.get('status') == 'pending' and old.get('phase') == 'post'
            and old.get('pending_checksum') == checksum
            and (p['mode'] == 'arc' or (old.get('pending_verification') == 'installer_result'
                                         and old.get('pending_installer_changed') is True))):
        op.update(action='recover', reason='post_recovery')
        return
    if not complete:
        op.update(action='install', reason='missing_confirmed_state')
        return
    same_version, same_hash = old_version == version, old_checksum.lower() == checksum
    if same_hash and not same_version:
        op['warning'] = 'Version differs but SHA-256 matches; ' + ('forced update' if p['force'] else 'treating artifact as unchanged')
    elif same_version and not same_hash:
        op['warning'] = 'Version matches but SHA-256 differs; updating artifact'
    if p['force'] or not same_hash:
        op.update(action='upgrade', reason='forced' if p['force'] else 'checksum_changed')
    else:
        op.update(action='skip', reason='state_current')


def state_package_plan(op, catalog, source, dest, snapshot, cache_dir=None):
    p = op['pattern']
    metadata = snapshot.get('msi_metadata') if p['mode'] == 'msi' else None
    artifact = select_artifact(p, catalog, source, metadata, cache_dir, snapshot.get('local_msi_errors'))
    op.update(artifact=artifact, verification='installer_result', installed={},
              cache_path=target(target(dest, '_src'), artifact['checksum'] + '/' + artifact['filename']))
    state_artifact_action(op)
    if p['mode'] == 'msi' and op['action'] in ('install', 'upgrade'):
        args = p.get('args') or []
        command = subprocess.list2cmdline(['msiexec.exe', '/i', op['cache_path'], '/qn', '/norestart', '/L*v', op['cache_path'] + '.log', 'REINSTALL=ALL', 'REINSTALLMODE=vomus'])
        op['msi_reinstall_command'] = command + (' ' + (args if isinstance(args, str) else subprocess.list2cmdline(args)) if args else '')
    return op


def stage_packages(operations, source, dest, cache_dir):
    if not cache_dir or not Path(cache_dir).is_dir():
        raise SoftwareError('Controller cache unavailable')
    root = target(dest, '_src')
    directory = tempfile.mkdtemp(prefix='packages-', dir=cache_dir)
    paths = []
    try:
        for op in operations:
            if op['action'] not in ('install', 'upgrade') or op['pattern']['mode'] not in ('exe', 'msi'):
                continue
            artifact = op['artifact']
            checksum = artifact['checksum']
            if not re.fullmatch(r'[0-9a-f]{64}', checksum):
                raise SoftwareError('Invalid installer checksum')
            filename = relative(artifact['filename'])
            if '/' in filename or op['cache_path'] != target(root, checksum + '/' + filename):
                raise SoftwareError('Invalid installer cache path')
            src = source_file(source, artifact['source'])
            dst = Path(directory) / checksum / filename
            dst.parent.mkdir(exist_ok=True)
            if cached_sha(src, cache_dir) != checksum:
                raise SoftwareError('Artifact changed since planning: ' + filename)
            shared = Path(cache_dir) / ('staged-' + checksum)
            with open(str(shared) + '.lock', 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if not shared.exists():
                    fd, temp = tempfile.mkstemp(prefix='staged-', dir=cache_dir)
                    os.close(fd)
                    try:
                        shutil.copyfile(src, temp)
                        if sha(temp) != checksum:
                            raise SoftwareError('Artifact changed during staging: ' + filename)
                        os.replace(temp, shared)
                    finally:
                        if os.path.exists(temp):
                            os.unlink(temp)
                os.link(shared, dst)
            paths.append(op['cache_path'])
            if op['pattern']['mode'] == 'msi':
                paths.append(op['cache_path'] + '.log')
        return {'directory': directory, 'paths': paths, 'root': root}
    except BaseException:
        shutil.rmtree(directory)
        raise


def stage_files(files, root, cache_dir, snapshot=None):
    if not cache_dir or not Path(cache_dir).is_dir():
        raise SoftwareError('Controller cache unavailable')
    root = winroot(root)
    directory = tempfile.mkdtemp(prefix='files-', dir=cache_dir)
    count = 0
    try:
        for f in files:
            path = winroot(f['path'])
            if not inside(path, root):
                raise SoftwareError('File escapes managed root')
            if (snapshot or {}).get(f['path']) == f['checksum']:
                continue
            rel = relative(ntpath.relpath(path, root))
            dst = Path(directory) / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if 'content_b64' in f:
                raise SoftwareError('Templates must use atomic template writer')
            shutil.copyfile(f['source'], dst)
            if sha(dst) != f['checksum']:
                raise SoftwareError('Staged file checksum mismatch: ' + rel)
            count += 1
        return {'directory': directory, 'root': root, 'count': count}
    except BaseException:
        shutil.rmtree(directory)
        raise


def file_snapshot_value(snapshot, path):
    if path not in snapshot:
        raise SoftwareError('Missing file inspection result: ' + path)
    value = snapshot[path]
    if isinstance(value, dict):
        raise SoftwareError('File inspection failed: ' + path + ': ' + str(value.get('error', 'invalid inspection result')))
    return value


def plan_files(op, files, snapshot):
    old, p = op['old'], op['pattern']
    manifest = [{'path': f['path'], 'checksum': f['checksum']} for f in files]
    changed = False
    for f in op['remove']:
        actual = file_snapshot_value(snapshot, f['path'])
        if actual is not None:
            if 'checksum' in f and actual != f['checksum']:
                raise SoftwareError('Managed file changed outside Ansible: ' + f['path'])
            changed = True
    for f in manifest:
        actual = file_snapshot_value(snapshot, f['path'])
        if actual != f['checksum']:
            changed = True
    if changed or p['force'] or (op.get('state_update') and op['action'] != 'recover'):
        action = 'update_files'
    elif old.get('status') == 'pending':
        action = 'recover' if old.get('phase') == 'post' else 'update_files'
    elif p['state'] == 'absent' and old and old.get('status') != 'absent':
        action = 'forget'
    elif p['state'] == 'present' and (old.get('files', []) != manifest or old.get('checksum') != op['artifact'].get('checksum') or old.get('status') != 'installed'):
        action = 'adopt'
    else:
        action = 'skip'
    run_pre = action == 'update_files'
    if 'hook_timeout_seconds' in op:
        validate_operation_timeouts(op, action, run_pre)
    return {'action': action, 'run_pre': run_pre}


def verify_files(op, files, snapshot):
    for f in files:
        if file_snapshot_value(snapshot, f['path']) != f['checksum']:
            raise SoftwareError('Managed file checksum mismatch: ' + f['path'])
    for f in op['remove']:
        if file_snapshot_value(snapshot, f['path']) is not None:
            raise SoftwareError('Managed file was not removed: ' + f['path'])
    return {'verified': True}


def refresh_artifact_version(op):
    old, artifact = op['old'], op['artifact']
    if op['action'] != 'skip' or not op.get('warning') or old.get('artifact_version', old.get('version')) == artifact['version']:
        return None
    if old.get('artifact_checksum', old.get('checksum', '')).lower() != artifact['checksum']:
        return None
    record = dict(old, version=artifact['version'])
    if op['pattern']['mode'] in ('exe', 'msi') or 'artifact_version' in old:
        record['artifact_version'] = artifact['version']
    return record


def timeout_value(value, name):
    if not re.fullmatch(r'[0-9]+', str(value)) or not 5 <= int(value) <= 86400:
        raise SoftwareError(name + ' must be an integer between 5 and 86400 seconds.')
    return int(value)


def validate_operation_timeouts(op, action, run_pre):
    p = op['pattern']
    if action in ('install', 'upgrade', 'remove'):
        timeout_value(op['package_timeout_seconds'], 'package_timeout / software_package_timeout')
    if (run_pre and p['pre']) or (action in ('install', 'upgrade', 'remove', 'update_files', 'recover') and p['post']):
        timeout_value(op['hook_timeout_seconds'], 'hook_timeout / software_hook_timeout')


def inspection_batches(operations):
    paths = []
    for op in reversed(operations):
        if op['pattern']['mode'] not in ('files', 'arc'):
            paths = []
            continue
        paths = list(dict.fromkeys([f['path'] for f in op['files'] + op['remove']] + paths))
        op['inspection_paths'] = paths


def file_preflight(operations):
    count = 0
    templates = []
    for index, op in enumerate(operations):
        p = op['pattern']
        if p['mode'] not in ('arc', 'files'):
            break
        count += 1
        if p['mode'] == 'files' and p['template'] and p['state'] == 'present':
            templates.extend({'index': index, 'file': f} for f in op['files'])
    return {'count': count, 'paths': operations[0]['inspection_paths'] if count else [], 'templates': templates}


def prune_file_operations(operations, snapshot, rendered):
    skipped = []
    for op in operations:
        p = op['pattern']
        if p['mode'] not in ('arc', 'files'):
            break
        files = op['files']
        if p['mode'] == 'files' and p['template'] and p['state'] == 'present':
            checksums = rendered.get(op['id'], {})
            if any(not re.fullmatch(r'[0-9a-f]{64}', str(checksums.get(f['path'], ''))) for f in files):
                break
            files = [dict(f, checksum=checksums[f['path']]) for f in files]
        try:
            decision = plan_files(op, files, snapshot)
        except SoftwareError:
            break
        if decision['action'] != 'skip':
            break
        skipped.append({'id': op['id'], 'reason': 'already_current'})
    return {'execution_indices': list(range(len(skipped), len(operations))), 'skipped': skipped}


def make_plan(patterns, catalog, source, snapshot, db, dest, cache_dir=None, timeouts=None):
    timeouts = timeouts or {}
    operations, skipped, errors, blocked, warnings = [], [], [], [], []
    state_refresh = {}
    owners = {}
    package_owners = {}
    artifact_owners = {}
    stored_owners = {}
    for owner, record in db['products'].items():
        if record.get('status') == 'absent':
            continue
        for f in record.get('files', []):
            path = f['path'].casefold()
            if path in stored_owners and stored_owners[path] != owner:
                raise SoftwareError('Conflicting ownership in state database')
            stored_owners[path] = owner
    reserved = [target(dest, '_state'), target(dest, '_src')]
    for p in patterns:
        key = p['id']
        old = db['products'].get(key, {})
        native_msi = p['mode'] == 'msi' and 'msi_metadata' in snapshot
        try:
            op = {'id': key, 'pattern': p, 'old': old, 'files': [], 'remove': [], 'artifact': {}, 'action': 'inspect'}
            if p['mode'] in ('exe', 'msi') and p['state'] == 'present':
                op = state_package_plan(op, catalog, source, dest, snapshot, cache_dir)
                identities = [('resolved_product_id' if field == 'product_id' else field, p[field].casefold()) for field in ('product_id', 'name', 'uninstall_name_regex', 'creates_path') if p.get(field)]
                meta = op['artifact'].get('msi_metadata')
                if meta:
                    identities.append(('msi_family', (meta.get('upgrade_code') or meta['product_id']).casefold()))
                    identities.append(('resolved_product_id', meta['product_id'].casefold()))
                for identity in identities:
                    if identity in package_owners and package_owners[identity] != key:
                        raise SoftwareError('Conflicting package identities')
                    package_owners[identity] = key
            elif p['mode'] in ('exe', 'msi'):
                if native_msi:
                    if p.get('product_id') and guid(p['product_id']):
                        op['msi_identity'] = {'product_id': p['product_id']}
                    elif old.get('status') in ('installed', 'installer_reported', 'pending', 'absent') and valid_msi_metadata(old.get('msi_metadata')) and not any(p.get(x) for x in ('product_id', 'name', 'uninstall_name_regex')):
                        op['msi_identity'] = old['msi_metadata']
                app = package_app(op, snapshot)
                probe = snapshot.get('probes', {}).get(p.get('creates_path', ''), {})
                if app is None and probe.get('exists') and not op['artifact'].get('msi_metadata') and not op.get('msi_identity'):
                    app = {'version': probe.get('version'), 'probe_only': True}
                op['installed'] = app or {}
                identities = [('resolved_product_id' if field == 'product_id' else field, p[field].casefold()) for field in ('product_id', 'name', 'uninstall_name_regex', 'creates_path') if p.get(field)]
                if app and app.get('product_id'):
                    identities.append(('resolved_product_id', app['product_id'].casefold()))
                if op.get('msi_identity'):
                    meta = op['msi_identity']
                    identities.append(('msi_family', (meta.get('upgrade_code') or meta['product_id']).casefold()))
                if app and app.get('registry_key'):
                    identities.append(('registry_key', app['registry_key'].casefold()))
                for identity in identities:
                    if identity in package_owners and package_owners[identity] != key:
                        raise SoftwareError('Conflicting package identities')
                for identity in identities:
                    package_owners[identity] = key
                if not op.get('msi_identity') and not any(p.get(x) for x in ('name', 'product_id', 'uninstall_name_regex')):
                    if not app and (not old or old.get('status') == 'absent'):
                        skipped.append({'id': key, 'reason': 'no_removal_identity'})
                        continue
                    raise SoftwareError('Removal requires registry identity')
                if app:
                    if not app.get('product_id') or '\\' in app['product_id'] or '/' in app['product_id'] or app.get('probe_only') or sum(1 for entry in snapshot['installed'] if (entry.get('product_id') or '').casefold() == app['product_id'].casefold()) != 1:
                        raise SoftwareError('No reliable uninstall identity')
                    if app['provider'] == 'registry' and not app.get('quiet_uninstall_string') and not p.get('uninstall_args'):
                        raise SoftwareError('Explicit silent uninstall arguments required')
                    op['action'] = 'remove'
                else:
                    op['action'] = 'recover' if old.get('status') == 'pending' else ('forget' if old and old.get('status') != 'absent' else 'skip')
            elif p['state'] == 'present':
                if p['mode'] == 'arc':
                    op['artifact'] = select_artifact(p, catalog, source, cache_dir=cache_dir)
                    state_artifact_action(op)
                    if op['action'] == 'skip':
                        if op.get('warning'):
                            warnings.append({'id': key, 'filename': op['artifact']['filename'], 'status': 'warning', 'action': 'skip', 'reason': op['warning']})
                        refreshed = refresh_artifact_version(op)
                        if refreshed is not None:
                            state_refresh[key] = refreshed
                        skipped.append({'id': key, 'reason': op['reason']})
                        continue
                    op['action'] = 'recover' if op['action'] == 'recover' else 'inspect'
                    op['state_update'] = True
                op['files'] = file_manifest(p, op['artifact'], source, cache_dir)
                paths = {f['path'].casefold() for f in op['files']}
                op['remove'] = [f for f in old.get('files', []) if f['path'].casefold() not in paths]
            else:
                op['remove'] = old.get('files', [])
                if not op['remove'] and p['files']:
                    op['remove'] = [{'path': target(p['root'], os.path.basename(f) if p['mode'] == 'arc' and p['archive_layout'] == 'flat' else f)} for f in p['files']]
                if not op['remove'] and p['mode'] == 'arc':
                    if old.get('status') == 'absent':
                        skipped.append({'id': key, 'reason': 'already_absent'})
                        continue
                    raise SoftwareError('No owned manifest for archive removal; specify files explicitly')
            for f in op['files'] + op['remove']:
                path = winroot(f['path'])
                if not inside(path, p['root']) or any(path.casefold() == r.casefold() or inside(path, r) for r in reserved):
                    raise SoftwareError('File escapes managed destination or touches service data')
                owner = owners.get(path.casefold(), stored_owners.get(path.casefold()))
                if owner is not None and owner != key:
                    raise SoftwareError('Conflicting managed file ownership: ' + path)
            current_paths = [f['path'].casefold() for f in op['files'] + op['remove']]
            if len(set(current_paths)) != len(current_paths):
                raise SoftwareError('Duplicate destination in product')
            for path in current_paths:
                if any(inside(path, other) or inside(other, path) for other in owners):
                    raise SoftwareError('Overlapping managed paths')
                owners[path] = key
            if p['mode'] in ('exe', 'msi'):
                op['run_pre'] = op['action'] in ('install', 'upgrade', 'remove')
            op['package_timeout_seconds'] = p.get('package_timeout', timeouts.get('package', 900))
            op['hook_timeout_seconds'] = p.get('hook_timeout', timeouts.get('hook', 120))
            if p['mode'] in ('exe', 'msi') and op['artifact']:
                path = op['artifact']['checksum']
                if path in artifact_owners and artifact_owners[path] != key:
                    errors.append({'id': key, 'reason': 'Installer selected by multiple patterns: ' + artifact_owners[path]})
                    continue
                artifact_owners[path] = key
            if p['mode'] in ('exe', 'msi'):
                try:
                    validate_operation_timeouts(op, op['action'], op.get('run_pre', False))
                except SoftwareError as exc:
                    blocked.append({'id': key, 'filename': op['artifact'].get('filename', op.get('installed', {}).get('name', key)), 'status': 'error', 'action': 'plan', 'reason': str(exc)})
                    continue
            if op.get('warning'):
                warnings.append({'id': key, 'filename': op['artifact']['filename'], 'status': 'warning', 'action': op['action'], 'reason': op['warning']})
            if op['action'] == 'skip':
                refreshed = refresh_artifact_version(op) if op['artifact'] else None
                if refreshed is not None:
                    state_refresh[key] = refreshed
                skipped.append({'id': key, 'reason': op.get('reason', 'already_current')})
            else:
                operations.append(op)
        except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError) as exc:
            if p['mode'] in ('exe', 'msi'):
                if str(exc).startswith('Conflicting package identities'):
                    errors.append({'id': key, 'reason': str(exc)})
                    continue
                blocked.append({'id': key, 'filename': op.get('artifact', {}).get('filename', key), 'status': 'error', 'action': 'plan', 'reason': str(exc)})
            else:
                errors.append({'id': key, 'reason': str(exc)})
    inspection_batches(operations)
    return {'operations': operations, 'skipped': skipped, 'errors': errors, 'blocked': blocked, 'warnings': warnings, 'state_refresh': state_refresh, 'file_preflight': file_preflight(operations)}


def prepare(op, source, cache_dir=None):
    artifact = op['artifact']
    path = source_file(source, artifact['source'])
    if cached_sha(path, cache_dir) != artifact['checksum']:
        raise SoftwareError('Artifact changed since planning')

    def unpack(directory):
        archive_members(path, extract_to=directory)
        if sha(path) != artifact['checksum']:
            raise SoftwareError('Archive changed during preparation')

    def result(directory):
        files = []
        for f in op['files']:
            src = str(Path(directory) / relative(f['relative']))
            if cached_sha(src, cache_dir) != f['checksum']:
                raise SoftwareError('Extracted file checksum mismatch')
            files.append(dict(f, source=src))
        return {'directory': directory, 'files': files}

    if cache_dir:
        checksum = artifact['checksum']
        if not re.fullmatch(r'[0-9a-f]{64}', checksum):
            raise SoftwareError('Invalid archive checksum')
        shared = Path(cache_dir) / ('extracted-' + checksum)
        with open(str(shared) + '.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if not shared.exists():
                directory = tempfile.mkdtemp(prefix='extract-', dir=cache_dir)
                try:
                    unpack(directory)
                    os.replace(directory, shared)
                finally:
                    if os.path.isdir(directory):
                        shutil.rmtree(directory)
            return result(str(shared))
    directory = tempfile.mkdtemp(prefix='software-manager-')
    try:
        unpack(directory)
        return result(directory)
    except BaseException:
        shutil.rmtree(directory)
        raise


def verify_package(op, snapshot, receipt=None, before=None, hints=None):
    p = op['pattern']
    if op.get('verification') == 'installer_result':
        if p['state'] != 'present':
            raise SoftwareError('Legacy removal cannot be verified')
        if op['action'] == 'recover':
            old = op['old']
            if not (old.get('status') == 'pending' and old.get('phase') == 'post'
                    and old.get('pending_verification') == 'installer_result'
                    and old.get('pending_installer_changed') is True
                    and old.get('pending_checksum') == op['artifact']['checksum']):
                raise SoftwareError('No successful installer receipt for recovery')
        else:
            if not receipt or receipt.get('failed') or receipt.get('skipped') or receipt.get('unreachable'):
                raise SoftwareError('No successful installer result')
            if 'rc' in receipt and receipt['rc'] not in p['expected_return_code']:
                raise SoftwareError('Installer returned an unexpected code')
            if receipt.get('changed') is not True:
                raise SoftwareError('Installer did not perform the requested operation')
        if before is not None and snapshot.get('installed') and hints:
            app = learn_from_change(before.get('installed', []), snapshot['installed'], hints)
            if app:
                wanted = compare_package_version(op['artifact'].get('version'), op)
                actual = compare_package_version(app.get('version'), op)
                if wanted is None or (actual is not None and actual >= wanted):
                    return {'verification': 'learned_registry', 'identity': identity_record(app), 'installed_version': app.get('version')}
        return {'verification': 'installer_result'}
    app = package_app(op, snapshot)
    probe = snapshot.get('probes', {}).get(p.get('creates_path', ''), {})
    if p['state'] == 'absent':
        if app or probe.get('exists'):
            raise SoftwareError('Product is still present')
        return {'verification': 'installed_state'}
    if p.get('creates_path') and not probe.get('exists'):
        raise SoftwareError('Required installed file not found: ' + p['creates_path'])
    if not app and not probe.get('exists'):
        raise SoftwareError('Installed product not found: ' + op['artifact'].get('filename', op['id']))
    wanted = compare_package_version(op['artifact'].get('version'), op)
    installed_version = (app or {}).get('version') or probe.get('version')
    actual = compare_package_version(installed_version, op)
    previous = compare_package_version(op.get('installed', {}).get('version'), op)
    downgrade = p['allow_downgrade'] and previous is not None and wanted is not None and previous > wanted and op['action'] == 'upgrade'
    if wanted is not None and actual is not None and (actual < wanted or (downgrade and actual != wanted)):
        raise SoftwareError('Installed version does not match planned version: ' + str(installed_version) + ' vs ' + str(op['artifact'].get('version')))
    if wanted is not None and actual is None and not p['allow_unknown_version']:
        raise SoftwareError('Installed version cannot be verified')
    if op.get('artifact', {}).get('msi_metadata') and not app:
        raise SoftwareError('MSI product not found')
    if op.get('artifact', {}).get('msi_metadata') and op['action'] in ('install', 'upgrade', 'recover'):
        if (app.get('product_id') or '').casefold() != op['artifact']['msi_metadata']['product_id'].casefold():
            raise SoftwareError('Target MSI ProductCode not found after operation')
    verification = 'msi' if op.get('artifact', {}).get('msi_metadata') else 'registry' if app else 'file_version'
    return {'verification': verification, 'identity': identity_record(app), 'installed_version': installed_version}


def transition(db, op, phase, files, reboot=False, verified=None):
    db = normalize_state(db)
    result = json.loads(json.dumps(db))
    p = op['pattern']
    key = op['id']
    if phase == 'done' and p['state'] == 'absent':
        if p['mode'] == 'arc' and not p['files']:
            result['products'][key] = {'status': 'absent', 'mode': 'arc', 'files': op['remove']}
        elif p['mode'] == 'msi' and valid_msi_metadata(op.get('msi_identity')):
            result['products'][key] = {'status': 'absent', 'mode': 'msi', 'msi_metadata': op['msi_identity']}
        else:
            result['products'].pop(key, None)
    elif phase in ('pending', 'post'):
        previous = result['products'].get(key, {})
        result['products'][key] = dict(previous, status='pending', phase=phase, pending_checksum=op['artifact'].get('checksum'), reboot_required=reboot)
        if op['artifact'].get('msi_metadata'):
            result['products'][key]['pending_msi_metadata'] = op['artifact']['msi_metadata']
        else:
            result['products'][key].pop('pending_msi_metadata', None)
        if phase == 'post':
            result['products'][key]['pending_installer_changed'] = bool((verified or {}).get('installer_changed'))
        else:
            result['products'][key].pop('pending_installer_changed', None)
        if phase == 'post' and op.get('verification') == 'installer_result':
            result['products'][key]['pending_verification'] = 'installer_result'
        else:
            result['products'][key].pop('pending_verification', None)
    else:
        result['products'][key] = {'status': 'installed', 'mode': p['mode'], 'version': op['artifact'].get('version'), 'checksum': op['artifact'].get('checksum'), 'files': [{'path': f['path'], 'checksum': f['checksum']} for f in files], 'reboot_required': reboot}
        record = result['products'][key]
        if p['mode'] in ('exe', 'msi'):
            record['artifact_version'] = op['artifact'].get('version')
            record['artifact_checksum'] = op['artifact'].get('checksum')
            details = verified or {}
            record['installed_version'] = details.get('installed_version', op.get('installed', {}).get('version') or (op['artifact'].get('version') if op.get('verification') != 'installer_result' else None))
            if op['action'] in ('install', 'upgrade') and details.get('installer_changed') is True:
                record['applied_checksum'] = op['artifact'].get('checksum')
            elif op['action'] == 'recover' and op['old'].get('pending_checksum') == op['artifact'].get('checksum') and op['old'].get('phase') == 'post' and op['old'].get('pending_installer_changed') is True:
                record['applied_checksum'] = op['artifact'].get('checksum')
            elif op['old'].get('applied_checksum'):
                record['applied_checksum'] = op['old']['applied_checksum']
            record['verification'] = details.get('verification', op.get('verification', 'installed_state'))
            if details.get('identity'):
                record['identity'] = details['identity']
            elif op['old'].get('identity'):
                record['identity'] = op['old']['identity']
            if record['verification'] == 'installer_result':
                record['status'] = 'installer_reported'
            if op['artifact'].get('msi_metadata'):
                record['msi_metadata'] = op['artifact']['msi_metadata']
    return result

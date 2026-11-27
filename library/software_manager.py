#!/usr/bin/python

import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils import software_core as core


def main():
    module = AnsibleModule(
        argument_spec={
            'operation': {'type': 'str', 'required': True, 'choices': ['index', 'normalize', 'discover_msi', 'plan', 'prepare', 'verify', 'transition', 'stage_packages', 'stage_files', 'plan_files', 'prune_files', 'verify_files']},
            'source': {'type': 'path', 'default': '/source'},
            'dest': {'type': 'str'},
            'layers': {'type': 'list', 'elements': 'dict', 'default': []},
            'identity_overrides': {'type': 'dict', 'default': {}},
            'patterns': {'type': 'list', 'elements': 'dict', 'default': []},
            'operations': {'type': 'list', 'elements': 'dict', 'default': []},
            'catalog': {'type': 'list', 'elements': 'str', 'default': []},
            'snapshot': {'type': 'dict', 'default': {}},
            'rendered': {'type': 'dict', 'default': {}},
            'timeouts': {'type': 'dict', 'default': {}},
            'before': {'type': 'dict', 'default': {}},
            'hints': {'type': 'dict', 'default': {}},
            'verified': {'type': 'dict', 'default': {}},
            'cache_dir': {'type': 'path'},
            'receipt': {'type': 'dict', 'default': {}},
            'state': {'type': 'raw', 'default': {}},
            'item': {'type': 'dict', 'default': {}},
            'files': {'type': 'list', 'elements': 'dict', 'default': []},
            'phase': {'type': 'str', 'choices': ['pending', 'post', 'done']},
            'reboot': {'type': 'bool', 'default': False},
        },
        supports_check_mode=True,
        required_if=[('operation', 'normalize', ['dest']), ('operation', 'plan', ['dest']), ('operation', 'transition', ['phase'])],
    )
    p = module.params
    try:
        operation = p['operation']
        if operation == 'index':
            core.check_metadata_tools()
            result = {'catalog': core.index(p['source']), 'cache_dir': tempfile.mkdtemp(prefix='software-catalog-')}
        elif operation == 'normalize':
            result = {'patterns': core.merge(p['layers'], p['dest'], p['identity_overrides']), 'dest': core.winroot(p['dest'])}
        elif operation == 'discover_msi':
            result = core.discover_msi(p['patterns'], p['catalog'], p['source'], core.normalize_state(p['state']), p['cache_dir'])
        elif operation == 'plan':
            db = core.normalize_state(p['state'])
            plan = core.make_plan(p['patterns'], p['catalog'], p['source'], p['snapshot'], db, p['dest'], p['cache_dir'], p.get('timeouts', {}))
            plan_warnings = plan.pop('warnings', [])
            for warning in plan_warnings:
                module.warn(f"{warning['filename']}: {warning['reason']}")
            result = dict(plan, database=db, plan_warnings=plan_warnings)
        elif operation == 'prepare':
            if module.check_mode:
                module.exit_json(changed=False, skipped=True)
            result = core.prepare(p['item'], p['source'], p['cache_dir'])
        elif operation == 'stage_packages':
            if module.check_mode:
                module.exit_json(changed=False, skipped=True)
            result = core.stage_packages(p['operations'], p['source'], p['dest'], p['cache_dir'])
        elif operation == 'stage_files':
            if module.check_mode:
                module.exit_json(changed=False, skipped=True)
            result = core.stage_files(p['files'], p['dest'], p['cache_dir'], p['snapshot'])
        elif operation == 'plan_files':
            result = core.plan_files(p['item'], p['files'], p['snapshot'])
        elif operation == 'prune_files':
            result = core.prune_file_operations(p['operations'], p['snapshot'], p['rendered'])
        elif operation == 'verify_files':
            result = core.verify_files(p['item'], p['files'], p['snapshot'])
        elif operation == 'verify':
            details = core.verify_package(p['item'], p['snapshot'], p['receipt'], p['before'], p['hints'])
            result = dict(details, verified=details['verification'] != 'installer_result', installer_changed=p['receipt'].get('changed') is True)
        else:
            result = {'database': core.transition(p['state'], p['item'], p['phase'], p['files'], p['reboot'], p['verified'])}
        if operation in ('verify', 'verify_files') and p['phase'] == 'done':
            result['database'] = core.transition(p['state'], p['item'], 'done', p['files'], p['reboot'], result)
        module.exit_json(changed=False, **result)
    except Exception as exc:
        module.fail_json(msg=str(exc))


if __name__ == '__main__':
    main()

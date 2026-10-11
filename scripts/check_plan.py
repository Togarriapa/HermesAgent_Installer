#!/usr/bin/env python3
"""Validate the one current scope and its OpenSpec links, not runtime readiness."""
import argparse
import json
import re
import sys
from pathlib import Path


REQUIRED_COMPONENT_IDS = ('addy-osmani-s-agent-skills', 'adewaskar-jarvis', 'agent-memory', 'antropic-cybersecurity-skills', 'apple-design', 'awesome-design', 'awesome-harness-engineering', 'banana-claude', 'book-to-skill', 'browser-use', 'claude-free', 'claude-mem', 'cloudflare-access', 'cloudflare-tunnel', 'codex-account', 'colibri', 'coral', 'diagram-design', 'ecc', 'emil-kowalski-impeccable', 'emil-skills', 'figma-mcp', 'glm-5-2', 'google', 'google-calendar', 'google-community-mcp', 'google-contacts', 'google-docs', 'google-drive', 'google-gmail', 'google-sheets', 'graphify', 'gstack', 'hermes-agent', 'hermes-desktop', 'home-assistant', 'humanizer', 'hyperframes', 'jakeschincariol-replica-skill', 'latent-spaces-brag', 'nemotron-free', 'obsidian-skills', 'omniroute', 'open-executive', 'open-viking', 'openai-api', 'openrouter-account', 'panniantong-agent-reach', 'playwright-mcp', 'ponytail', 'public-apis-public-apis', 'remote-desktop-bridge', 'remote-desktop-html5', 'resource-registry', 'revenuecat-mcp', 'ruflo', 'scientific-agent-skills', 'scrapegraph-ai', 'screenshot-to-code', 'superpowers', 'taste-skill', 'ui-ux-pro-max')


class PlanError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PlanError(message)


def load(path):
    return json.loads(path.read_text())


def indexed(rows, label):
    require(isinstance(rows, list) and rows, f'Missing {label}')
    result = {}
    for row in rows:
        require(isinstance(row, dict), f'Invalid {label} row')
        key = row.get('id')
        require(isinstance(key, str) and key and key not in result, f'Duplicate/invalid {label} ID')
        result[key] = row
    return result


def linked(row, field, target, label):
    values = row.get(field)
    require(isinstance(values, list) and values and len(values) == len(set(values)), f'Missing/duplicate {label} {field}')
    require(all(value in target for value in values), f'Unknown {label} {field}')
    return values


def current_status(row, field, label):
    require(row.get(field) == 'OPEN', f'{label} falsely claims acceptance without release evidence')


def check_coverage(base):
    base = Path(base)
    scope = load(base / 'requirements/current-scope.json')
    require(scope.get('schema') == 1 and scope.get('change') == 'jarvis-core-platform', 'Unsupported current scope')
    require((base / 'CURRENT-PLAN.md').is_file(), 'Missing current plan entrypoint')
    change_root = base / 'openspec/changes'
    changes = {p.name for p in change_root.iterdir() if p.is_dir()}
    require(changes == {'jarvis-core-platform'}, 'Current OpenSpec must contain only jarvis-core-platform')
    change = change_root / 'jarvis-core-platform'
    artifacts = [change / 'proposal.md', change / 'design.md', change / 'tasks.md', change / 'specs/jarvis-core-platform/spec.md']
    for path in artifacts:
        require(path.is_file() and path.read_text().strip(), f'Missing current artifact {path.name}')
    specs = artifacts[3].read_text()
    task_text = artifacts[2].read_text()
    checkbox_ids = set(re.findall(r'^- \[[ xX]\]\s+(?:\d+(?:\.\d+)*\s+)?`?([A-Z]{2}-[A-Z]\d+(?:\.\d+)?)\b', task_text, re.M))
    requirements = indexed(scope.get('requirements'), 'requirement')
    tasks = indexed(scope.get('tasks'), 'task')
    components = indexed(scope.get('components'), 'component')
    acceptance = indexed(scope.get('acceptance'), 'acceptance')
    original_ids = {f'R{number:04}' for number in range(1, 212)}
    require(original_ids <= requirements.keys(), 'Original functional requirement omitted')
    required_core = {'CORE-SESSION', 'CORE-BOTS', 'CORE-LEASE', 'CORE-CLEANUP', 'CORE-RESOURCES', 'CORE-DOCS'}
    require(required_core <= requirements.keys(), 'Current core/security/cleanup/release obligation omitted')
    require(set(components) == set(REQUIRED_COMPONENT_IDS), 'Requested component inventory changed')
    require(set(acceptance) == {f'AC{number:02}' for number in range(1, 16)}, 'Acceptance coverage changed')
    required_tasks = {'BD-T266.1', 'HI-T266.2', 'RT-T266.3', 'RB-T266.4', 'VD-T266.5', 'BD-T267.1', 'VD-T267.2', 'VD-T268.1'}
    require(required_tasks <= tasks.keys(), 'Core/capability/UI/Resources/cleanup/release task omitted')
    for key, row in requirements.items():
        require(isinstance(row.get('text'), str) and row['text'].strip(), f'Missing requirement text {key}')
        require(row.get('phase') in range(1, 6), f'Invalid requirement phase {key}')
        require(row.get('task_id') in tasks, f'Unknown task for {key}')
        for field in ('implementation_module', 'verification_method', 'test_path'):
            require(isinstance(row.get(field), str) and row[field].strip(), f'Missing substantive {field} for {key}')
        require(re.search(r'^### Requirement:\s+' + re.escape(key) + r'(?:\s|:|$)', specs, re.M), f'Missing current spec requirement {key}')
        current_status(row, 'acceptance', key)
    for key, row in tasks.items():
        require(row.get('phase') in range(1, 6), f'Invalid task phase {key}')
        require(key in checkbox_ids, f'Missing current checkbox task {key}')
        require(isinstance(row.get('depends_on'), list), f'Missing task dependencies {key}')
        require(all(dep in tasks for dep in row['depends_on']), f'Unknown task dependency {key}')
        current_status(row, 'acceptance', key)
    active, done = set(), set()
    def visit(key):
        require(key not in active, f'Task dependency cycle {key}')
        if key in done:
            return
        active.add(key)
        for dep in tasks[key]['depends_on']:
            visit(dep)
        active.remove(key)
        done.add(key)
    for key in tasks:
        visit(key)
    for key, row in components.items():
        for field in ('requested_name', 'verification_method'):
            require(isinstance(row.get(field), str) and row[field].strip(), f'Missing component {field} {key}')
        require(isinstance(row.get('aliases'), list) and row['aliases'], f'Missing component aliases {key}')
        require(isinstance(row.get('source_urls'), list) and row['source_urls'], f'Missing component sources {key}')
        linked(row, 'requirement_ids', requirements, key)
        linked(row, 'task_ids', tasks, key)
        current_status(row, 'acceptance', key)
    for name, aliases in [('ecc', {'affaan-m/ECC', 'ecc'}), ('omniroute', {'OmniRoute', 'omniroute'}), ('playwright-mcp', {'playright', 'Playwright MCP'})]:
        require(aliases <= set(components[name]['aliases']), f'Requested alias omitted {name}')
    for key, row in acceptance.items():
        require(isinstance(row.get('text'), str) and row['text'].strip(), f'Missing acceptance assertion {key}')
        linked(row, 'requirement_ids', requirements, key)
        linked(row, 'task_ids', tasks, key)
        current_status(row, 'status', key)
    return {'requirements': len(requirements), 'tasks': len(tasks), 'inventory_records': len(components), 'acceptance_criteria': len(acceptance), 'current_artifacts': len(artifacts)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path('.'))
    args = parser.parse_args()
    try:
        stats = check_coverage(args.root)
        print(json.dumps({'planning_coverage': 'pass', 'runtime_acceptance': 'not-established', **stats}, indent=2))
        return 0
    except (PlanError, KeyError, TypeError, ValueError, OSError) as error:
        print('Current planning validation failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

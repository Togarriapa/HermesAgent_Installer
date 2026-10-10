"""Source-owned temporary fixture; no Pi, process or account acceptance.

Only the root TTY/principal/view custody entry seams are fixture observations.
Actual42 register_tool captures, held source bytes, four capture profiles,
owned overlay operations, schema CAS, role producer, projector and assembler
are the implementation under test.
"""
from __future__ import annotations

import builtins
import hashlib
import json
import os
import time
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace, FunctionType

import pytest

from hermes_installer.authority import bootstrap_runtime_factory as factory
from hermes_installer.authority import native_source_definitions as source_defs
from hermes_installer.authority import local_resource_effects as local
from hermes_installer.authority.native_definition_composition import RootSelectedNativeSourceComposer
from hermes_installer.authority.native_registration_projection import (
    RootNativeRegistrationProjectionRegistry, capture_actual_hermes_registrations,
    reviewed_packaged_registration_result_schemas, build_root_native_registration_projection,
    NativeRegistrationProjectionDenied,
)
from hermes_installer.authority.native_policy_preparation import (
    RootNativePolicyPreparationSelection, RootNativePolicyPreparationRegistry, _SELECTION_SEAL, _selection_payload, _canonical,
)
from hermes_installer.authority.native_assembler import assemble_native_package, NativeAssemblyDenied
from hermes_installer.registry.resources_runtime import ResourceOverlayStore
from hermes_installer.state import OwnedRoot, Journal

ROOT = Path(__file__).parents[2]


@pytest.fixture
def graph(tmp_path, monkeypatch):
    from hermes_installer.authority import native_schema_derivation
    # Fixture the root-only call gate; the schema CAS still checks actual file
    # UID/mode/inode/hash with the real OS module under this temporary root.
    class RootGate:
        def __getattr__(self, name):
            return (lambda: 0) if name == 'geteuid' else getattr(os, name)
    imports = dict(vars(builtins))
    original_import = builtins.__import__
    imports['__import__'] = lambda name, *args, **kwargs: RootGate() if name == 'os' else original_import(name, *args, **kwargs)
    original_argument = local.RootOwnerOverlaySchemaReceiptRegistry._argument_receipt
    monkeypatch.setattr(local.RootOwnerOverlaySchemaReceiptRegistry, '_argument_receipt',
                        FunctionType(original_argument.__code__, {**original_argument.__globals__, '__builtins__': imports},
                                     original_argument.__name__, original_argument.__defaults__))
    original_read = local.RootOwnerOverlaySchemaReceiptRegistry.read_current_argument_schema
    # Replace only the owner gate in its globals; CAS module uses real OS.
    monkeypatch.setattr(local.RootOwnerOverlaySchemaReceiptRegistry, 'read_current_argument_schema',
                        FunctionType(original_read.__code__, {**original_read.__globals__, '__builtins__': imports},
                                     original_read.__name__, original_read.__defaults__))
    session = object.__new__(factory.RootBootstrapSession)
    session._seal, session._closed = 'fixture-session', False
    session._handle = SimpleNamespace(session_id='fixture-session')
    session._factory = SimpleNamespace(_native_assembly_seal=object())
    session._native_assembly_definitions = {}
    session._native_assembly_member_owners = {}
    session._native_assembly_definition_contexts = {}
    session._native_assembly_selections = {}
    session._check_live = lambda: (_ for _ in ()).throw(PermissionError('closed fixture')) if session._closed else None
    binding = factory.RootSelectedInstallationBinding(session, session._seal)
    now = time.monotonic()
    selection = RootNativePolicyPreparationSelection(
        'policy-selection', 'choice', 'fixture-session', 'transaction', 'a'*64,
        'prepared-generation', 'b'*64, 'principal-selection', 'namespace-selection',
        'c'*64, 'd'*64, 'hermes-agent-native-v1', 'prepared-generation', 'resource-profile',
        'hermes-agent-native-package-v1', 'e'*64, ('resource-overlay-store',),
        tuple(sorted(local._REGISTRATIONS)), (), tuple(sorted(local._REGISTRATIONS)), (), (),
        None, 'setup-choice', 1, 'f'*64, 'controller', '1'*64, now, now+60, 0, _SELECTION_SEAL)
    selection=replace(selection,selection_sha256=hashlib.sha256(_canonical(_selection_payload(selection))).hexdigest())
    session.selection = selection
    session.resolve_current_native_policy_selection = lambda handle: current_selection(handle)
    def current_selection(handle):
        session._check_live()
        if handle != session.selection.selection_handle or session.selection.expires_monotonic <= time.monotonic():
            raise PermissionError('fixture choice changed or expired')
        return session.selection
    (tmp_path/'.hermes-installer-owned').write_text('schema=1\n')
    release_root = tmp_path/'release'
    release_root.mkdir()
    descriptors, receipt_map, fds = {}, {}, {}
    def retain(path, receipt_type, artifact=None):
        raw = (ROOT/path).read_bytes()
        destination = release_root/path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o644)
        artifact = artifact or 'installer-module:' + path.replace('/', '.')
        handle = 'source-' + hashlib.sha256(path.encode()).hexdigest()
        values = dict(artifact_id=artifact, relative_path=path, sha256=hashlib.sha256(raw).hexdigest(),
                      size_bytes=len(raw), release_commit='2'*40, deployment_receipt_sha256='3'*64,
                      source_receipt_handle=handle, _session_seal=session._seal, _session=session)
        if receipt_type is factory.RootReleaseModuleReceipt:
            values.update(_session_id='fixture-session', _prepared_generation_id='prepared-generation')
        else:
            values.update(setup_session_id='fixture-session', prepared_generation_id='prepared-generation',
                          _receipt_seal=factory._PREPARED_RELEASE_MEMBER_SEAL)
        receipt = receipt_type(**values)
        receipt_map[handle] = receipt
        descriptors[artifact] = SimpleNamespace(artifact_id=artifact, relative_path=path)
        fds[artifact] = os.open(destination, os.O_RDONLY)
        return receipt
    def read_member(receipt):
        session._check_live()
        if receipt_map.get(receipt.source_receipt_handle) is not receipt:
            raise PermissionError('fixture receipt substituted')
        raw = os.pread(fds[receipt.artifact_id], receipt.size_bytes + 1, 0)
        if len(raw) != receipt.size_bytes or hashlib.sha256(raw).hexdigest() != receipt.sha256:
            raise PermissionError('fixture source changed')
        return raw
    session._read_release_member_receipt = read_member
    session._read_prepared_release_member = read_member
    captured = capture_actual_hermes_registrations()
    receipts = tuple(retain('src/'+path, factory.RootReleaseModuleReceipt)
                     for path in sorted({row.registration_source_path for row in captured}))
    session._resolve_prepared_release_module_receipts = lambda: receipts
    workers = tuple(retain(row.release_member_path, factory.RootPreparedReleaseMemberReceipt)
                    for row in source_defs._ROLE_DECLARATIONS)
    profiles = tuple(retain(row.relative_path, factory.RootPreparedReleaseMemberReceipt, row.artifact_id)
                     for row in source_defs._CAPTURE_PROFILES)
    # Definition receipt has the installed lib/python path; fixture bytes are
    # the actual source module, held by FD rather than a caller DTO literal.
    path = 'src/hermes_installer/authority/native_source_definitions.py'
    definition = retain(path, factory.RootReleaseModuleReceipt)
    definition = replace(definition, relative_path='lib/python/hermes_installer/authority/native_source_definitions.py')
    receipt_map[definition.source_receipt_handle] = definition
    roles = source_defs.RootNativeSourceDefinitionRegistry(
        binding, lambda: workers, lambda: definition, capture_profile_receipt_provider=lambda: profiles,
        _seal=source_defs._REGISTRY_SEAL)
    source_bundle = roles.prepare_for_policy(selection)
    source = RootNativeRegistrationProjectionRegistry.from_root_setup(binding, tmp_path)
    coverage = source.resolve_source_coverage()
    assert len(coverage.source_observations) == 42 and len(coverage.component_ids) == 18
    result_map = {}
    for result in reviewed_packaged_registration_result_schemas(captured):
        if result.native_tool_name.startswith('resource_overlay_'):
            raw = (ROOT/result.relative_path).read_bytes()
            result_map[result.artifact_id] = (factory.RootNativeRegistrationSchemaReceipt(
                result.artifact_id, result.sha256, result.size_bytes, result.relative_path,
                'schema-'+result.artifact_id, 'fixture-session', 'transaction', 'prepared-generation',
                now+60, None, session._seal, session), raw)
    session._mint_native_registration_schema_receipt = lambda artifact: result_map[artifact][0]
    def read_result(receipt):
        session._check_live()
        retained, raw = result_map[receipt.artifact_id]
        if retained is not receipt or hashlib.sha256(raw).hexdigest() != receipt.sha256:
            raise PermissionError('fixture schema changed')
        return raw
    session._read_native_registration_schema_receipt = read_result
    overlay_root = tmp_path/'overlay'
    overlay_root.mkdir()
    (overlay_root/'.hermes-installer-owned').write_text('schema=1\n')
    owned_view = ResourceOverlayStore(OwnedRoot(overlay_root), Journal(tmp_path/'effects.sqlite3')).for_profile('hermes-agent-native-v1')
    effect_rules = tuple(local.RootPreparedOwnerOverlayEffectEnrollment(
        'effect-'+str(index), 'policy-selection', 'profile-view', operation,
        'plugin:resource-overlay-store', 'overlay-target', None, 'principal', 'hermes-agent-native-v1',
        'namespace', 'prepared-generation', now, now+60, local._ENROLLMENT_SEAL)
        for index, operation in enumerate(('plugin.resource-overlay-store.read','plugin.resource-overlay-store.write')))
    # Explicit fixture custody observation; no process or production UID proof.
    values = {f.name: '' for f in fields(local.RootPreparedOwnedProfileOverlayView)}
    values.update(schema=1, view_selection_handle='view-receipt', profile_view_selection_handle='profile-view',
                  native_policy_selection_handle='policy-selection', resource_profile_receipt_handle='resource-profile',
                  prepared_generation_id='prepared-generation', setup_session_id='fixture-session', transaction_handle='transaction',
                  service_profile_id='hermes-agent-native-v1', service_generation='prepared-generation',
                  principal_id='principal', namespace_id='namespace', target_id='overlay-target',
                  effect_enrollment_ids=tuple((r.operation,r.effect_enrollment_id) for r in effect_rules),
                  issued_monotonic=now, expires_monotonic=now+60, _seal=local._VIEW_SEAL,
                  _view=owned_view, _effect_rules=effect_rules, _data_root_fd=os.open(overlay_root,os.O_RDONLY),
                  _view_root_fd=os.open(overlay_root,os.O_RDONLY), resource_profile_id='basic',
                  prepared_generation_digest='b'*64, resources_source_sha256='5'*64,
                  ownership_marker_sha256=hashlib.sha256(b'schema=1\n').hexdigest(), view_mode=0o700)
    view = local.RootPreparedOwnedProfileOverlayView(**values)
    session._prepare_selected_profile_overlay_view = lambda *args: view
    session._resolve_current_profile_overlay_view = lambda *args: view
    class Targets:
        def resolve_current_owner_overlay_target(self, handle, selected_view, operation):
            current_selection(handle)
            if selected_view is not view:
                raise PermissionError('wrong view')
            return SimpleNamespace(selection_handle='target-selection',target_id='overlay-target'), next(r.effect_enrollment_id for r in effect_rules if r.operation == operation)
    journal = tmp_path/'journal'; journal.mkdir(mode=0o700)
    (journal/'.hermes-installer-owned').write_text('schema=1\n')
    targets=Targets()
    targets.bind_policy_selection=lambda row: setattr(session,'selection',row)
    target=SimpleNamespace(selection_handle='target-selection')
    targets.observe_selected_component_target=lambda *args: target
    targets.resolve_current_target=lambda *args: target
    policy=RootNativePolicyPreparationRegistry.from_root_setup(binding,object(),targets,binding,source,binding,journal)
    policy._validate_selection_context=lambda row: current_selection(row.selection_handle)
    policy.attach_source_definition_registry(roles)
    policy._selections[selection.selection_handle]=selection
    records=policy.prepare_selected_policy(selection.selection_handle)
    selection=policy.resolve_selection_current(selection.selection_handle)
    source_bundle=policy._source_definition_bundles[records.records_handle]
    composer=policy._selected_source_composer
    composition=policy._selected_source_compositions[records.records_handle]
    assert len(records.coverage_records)==42
    assert sum(row.configuration_state=='selected-complete' for row in records.coverage_records)==4
    assert all(row.missing_prerequisite_ids for row in records.coverage_records if row.configuration_state=='configurable-pending')
    session._native_policy_preparation_registry=policy
    session.resolve_current_prepared_native_policy_records=lambda handle: policy.resolve_prepared_policy(records.records_handle,binding)
    session._factory._release = SimpleNamespace(files=tuple(descriptors.values()), release_commit='2'*40,
                                                open_file=lambda artifact: os.dup(fds[artifact]))
    assembly_values = {f.name: '' for f in fields(factory.RootNativeBootstrapAssemblySelection)}
    assembly_values.update(schema=1, selection_handle='assembly-selection', service_profile_id=selection.service_profile_id,
                           service_generation=selection.service_generation, resource_profile_id='basic',
                           package_id=selection.package_id, native_package_generation=selection.native_package_generation,
                           prepared_generation_id='prepared-generation', compiler_artifact_id='installer-compiler',
                           compiler_sha256='4'*64, native_policy_preparation_handle='policy-selection',
                           issued_monotonic=now, expires_monotonic=now+60, _registry_seal=session._factory._native_assembly_seal)
    assembly = factory.RootNativeBootstrapAssemblySelection(**assembly_values)
    def revalidate(row):
        current_selection(row.native_policy_preparation_handle)
        if session._native_assembly_selections.get(row.selection_handle) is not row or row.expires_monotonic <= time.monotonic():
            raise PermissionError('fixture assembly changed')
    session._revalidate_native_assembly_selection = revalidate
    session._native_assembly_selections[assembly.selection_handle] = assembly
    definitions = session._retain_native_assembly_definitions(assembly, records)
    assembly = replace(assembly, definitions_sha256=definitions.definitions_sha256)
    session._native_assembly_selections[assembly.selection_handle] = assembly
    yield SimpleNamespace(session=session, binding=binding, selection=selection, assembly=assembly,
                          definitions=definitions, composer=composer, composition=composition,
                          result_map=result_map, receipt_map=receipt_map, fds=fds, records=records,
                          release_root=release_root)
    os.close(view._data_root_fd)
    os.close(view._view_root_fd)
    for fd in fds.values():
        os.close(fd)


def test_actual_source_owner_composition_projects_four_and_compiles_five_outputs(graph):
    definitions = graph.binding.resolve_native_assembly_definitions(graph.assembly.selection_handle)
    projection = build_root_native_registration_projection(graph.assembly, definitions)
    assert len(projection.registrations) == 4
    assert {row.handler_kind for row in projection.registrations} == {'owner-overlay'}
    assert graph.composer.resolve_current(graph.selection) is graph.composition
    assert len(graph.composition.operation_bundle.operation_records) == 4
    assert len(graph.composition.effect_policy_receipt_handles) == 2
    members = {row.artifact_receipt_handle: graph.binding.resolve_native_assembly_member(
        graph.assembly.selection_handle,row.artifact_receipt_handle) for row in definitions.closure_members}
    package = assemble_native_package(graph.assembly,definitions,members)
    resolver = json.loads(package.action_resolver)
    operation_rows = resolver["owner_overlay_operation_records"]
    assert [row["registration_id"] for row in operation_rows] == sorted(
        row["registration_id"] for row in operation_rows)
    assert {row["method"] for row in operation_rows} == {"read", "history", "write", "delete"}
    assert {row["registration_id"] for row in operation_rows} == {
        row.registration_id for row in projection.registrations}
    assert not any(row.get("action_id", row.get("id")) in {
        item["registration_id"] for item in operation_rows
    } for row in resolver.get("actions", []))
    altered_rows = list(definitions.owner_overlay_operation_records)
    altered_rows[0] = {**dict(altered_rows[0]), "profile_view_selection_handle": "forged-view"}
    with pytest.raises(NativeAssemblyDenied, match="source operation"):
        assemble_native_package(graph.assembly,
                                replace(definitions, owner_overlay_operation_records=tuple(altered_rows)),
                                members)
    assert all((package.entrypoint_manifest,package.action_resolver,package.boundary_overlay,
                package.compiled_closure,package.candidate_index))
    from hermes_installer.authority.native_output_receipts import _verify_payload, NativeOutputMember
    _verify_payload('native-compiled-closure','compiled-closure',package.compiled_closure,package.closure_members)
    for role,kind,path,raw in (
        ('native-entrypoint-manifest','entrypoint-json','manifest.json',package.entrypoint_manifest),
        ('native-action-resolver','resolver-json','resolver/resolver',package.action_resolver),
        ('native-boundary-overlay','boundary-overlay','overlay/manifest.json',package.boundary_overlay),
        ('native-candidate-index','candidate-index-json','catalog/native-candidates.json',package.candidate_index),
    ):
        _verify_payload(role,kind,raw,(NativeOutputMember(path,hashlib.sha256(raw).hexdigest(),len(raw),0o644),))

    with pytest.raises(TypeError):
        definitions.registration_records[0]['handler_id'] = 'substitution'


@pytest.mark.parametrize('kind',['missing','extra','choice','schema','source','expired','unknown-member','member-bytes'])
def test_selected_closure_substitution_denies_before_assembly(graph, kind):
    definitions, selection, session = graph.definitions,graph.assembly,graph.session
    if kind in {'missing','extra'}:
        rows=definitions.registration_records[:-1] if kind=='missing' else definitions.registration_records+(definitions.registration_records[0],)
        bad=replace(definitions,registration_records=rows)
        session._native_assembly_definitions[selection.selection_handle]=bad
        with pytest.raises(NativeRegistrationProjectionDenied):
            build_root_native_registration_projection(selection,bad)
    elif kind=='choice':
        session.selection=replace(graph.selection, selected_owner_overlay_registration_ids=())
        with pytest.raises((PermissionError, factory.BootstrapEnrollmentPending)):
            graph.binding.resolve_native_assembly_definitions(selection.selection_handle)
    elif kind=='schema':
        key=next(iter(graph.result_map)); receipt,_raw=graph.result_map[key]
        graph.result_map[key]=(receipt,b'{}')
        with pytest.raises((PermissionError, factory.BootstrapEnrollmentPending)):
            graph.binding.resolve_native_assembly_definitions(selection.selection_handle)
    elif kind=='source':
        row=definitions.closure_members[0]
        owner=graph.receipt_map[row.artifact_receipt_handle]
        path=graph.release_root/owner.relative_path
        path.write_bytes(b'changed source')
        with pytest.raises((PermissionError, factory.BootstrapEnrollmentPending)):
            graph.binding.resolve_native_assembly_definitions(selection.selection_handle)
    elif kind=='expired':
        session._native_assembly_selections[selection.selection_handle]=replace(selection,expires_monotonic=0)
        with pytest.raises((PermissionError, factory.BootstrapEnrollmentPending)):
            graph.binding.resolve_native_assembly_definitions(selection.selection_handle)
    elif kind=='unknown-member':
        with pytest.raises((PermissionError, factory.BootstrapEnrollmentPending)):
            graph.binding.resolve_native_assembly_member(selection.selection_handle,'outside-closure')
    else:
        members={row.artifact_receipt_handle:b'substituted' for row in definitions.closure_members}
        with pytest.raises(NativeAssemblyDenied):
            assemble_native_package(selection,definitions,members)

@pytest.mark.parametrize('kind',['omitted-member','mode','schema-cas','source-receipt','role-receipt'])
def test_held_member_and_schema_receipt_identity_cannot_be_substituted(graph,kind):
    definitions,session,selection=graph.definitions,graph.session,graph.assembly
    if kind=='omitted-member':
        session._native_assembly_definitions[selection.selection_handle]=replace(definitions,closure_members=definitions.closure_members[:-1])
    elif kind=='mode':
        member=definitions.closure_members[0]
        owner=graph.receipt_map[member.artifact_receipt_handle]
        (graph.release_root/owner.relative_path).chmod(0o600)
    elif kind=='schema-cas':
        receipt=next(row for row in graph.composition.schema_receipts if isinstance(row,local.RootOwnerOverlayArgumentSchemaReceipt))
        cas=receipt._registry._argument_store._root/receipt.relative_path
        cas.write_bytes(b'{}')
    elif kind=='source-receipt':
        member=definitions.closure_members[0]
        old=graph.receipt_map[member.artifact_receipt_handle]
        graph.receipt_map[member.artifact_receipt_handle]=replace(old,source_receipt_handle='substituted-receipt')
    else:
        roles=graph.composer._roles
        source_bundle=roles._bundles[graph.selection.selection_handle]
        roles._bundles[graph.selection.selection_handle]=replace(source_bundle,role_module_receipts=())
    with pytest.raises((PermissionError,factory.BootstrapEnrollmentPending)):
        graph.binding.resolve_native_assembly_definitions(selection.selection_handle)

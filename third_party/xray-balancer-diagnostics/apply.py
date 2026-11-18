"""Add the private selection observer to a disposable Xray 26.11.9 source copy."""

import hashlib
from pathlib import Path
import shutil


HERE = Path(__file__).resolve().parent
ROUTER = 'app/router/router.go'
RULE = 'app/router/config.go'
DISPATCHER = 'app/dispatcher/default.go'
HELPER = 'app/dispatcher/balancer_diagnostics.go'
CLI = 'main/native_balancer_cli.go'

UPSTREAM_SHA256 = {
    ROUTER: '1a0713181e73ea779d0b8ec5dc851f4a9ea4b97ba356253709c6bfecce2a3573',
    RULE: 'fcb133c67d62538e40b7ac747a865127b4ad9fae2ea9bae4859089d94a679af2',
    DISPATCHER: '29100330a020d75b5f4b77b8eec20779960a8768e765c99c1003e2b1475746fb',
}


def apply(source, destination, *, routing, cli=False):
    for name, expected in UPSTREAM_SHA256.items():
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != expected:
            raise ValueError('Pinned balancer diagnostics source mismatch: ' + name)

    replacements = {
        RULE: [('Balancer  *Balancer\n', 'Balancer  *Balancer\n\tbalancerTag string\n')],
        ROUTER: [
            ('\t\t\trr.Balancer = brule\n', '\t\t\trr.Balancer = brule\n\t\t\trr.balancerTag = btag\n'),
            ('\treturn &Route{Context: ctx, outboundTag: tag, ruleTag: rule.RuleTag}, nil',
             '\tselected := &Route{Context: ctx, outboundTag: tag, ruleTag: rule.RuleTag}\n'
             '\tif rule.balancerTag != "" { selected.outboundGroupTags = []string{rule.balancerTag} }\n'
             '\treturn selected, nil'),
        ],
        DISPATCHER: [
            ('type DefaultDispatcher struct {\n', 'type DefaultDispatcher struct {\n\tbalancerObserver *balancerObserver\n'),
            ('\t\td := new(DefaultDispatcher)\n',
             '\t\td := new(DefaultDispatcher)\n\t\td.balancerObserver = balancerObserverFromContext(ctx)\n'),
            ('\tvar handler outbound.Handler\n', '\tvar handler outbound.Handler\n\tvar selectedRoute routing.Route\n'),
            ('\t\t\t\tisPickRoute = 2\n', '\t\t\t\tisPickRoute = 2\n\t\t\t\tselectedRoute = route\n'),
            ('\thandler.Dispatch(ctx, link)\n', '\td.balancerObserver.record(ctx, selectedRoute, handler.Tag())\n\thandler.Dispatch(ctx, link)\n'),
        ],
    }
    if routing:
        replacements[DISPATCHER].insert(-1, (
            '\t\t\tif handler == nil { interruptNativeRouting(link); return }\n',
            '\t\t\tif handler == nil { interruptNativeRouting(link); return }\n\t\t\tselectedRoute = route\n',
        ))
    patched = {}
    for name, changes in replacements.items():
        contents = (destination / name).read_text()
        for before, after in changes:
            if contents.count(before) != 1:
                raise ValueError('Pinned balancer diagnostics patch boundary mismatch: ' + name)
            contents = contents.replace(before, after)
        patched[name] = contents
    overlays = [HELPER, CLI] if cli else [HELPER]
    for name in overlays:
        path = destination / name
        if path.exists() or path.is_symlink():
            raise ValueError('Balancer diagnostics overlay already exists: ' + name)
    for name, contents in patched.items():
        (destination / name).write_text(contents)
    for name in overlays:
        shutil.copyfile(HERE / 'overlay' / name, destination / name)

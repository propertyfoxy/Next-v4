
WHITELIST_PATHS = [
    '/acme/acme/',
    '/certbot-ci/',
    '/certbot-compatibility-test/',
]


class ForbidStandardOsModule(BaseChecker):
    """
    This checker ensures that standard os module (and submodules) is not imported by certbot
    modules. Otherwise an 'os-module-forbidden' error will be registered for the faulty lines.
    """

    name = 'forbid-os-module'
    msgs = {
        'E5001': (
            'Forbidden use of os module, certbot.compat.os must be used instead',
            'os-module-forbidden',
            'Some methods from the standard os module cannot be used for security reasons on '
            'Windows: the safe wrapper certbot.compat.os must be used instead in Certbot.'
        )
    }
    priority = -1

    def visit_import(self, node):
        os_used = any(name for name in node.names if name[0] == 'os' or name[0].startswith('os.'))
        if os_used and not _check_disabled(node):
            self.add_message('os-module-forbidden', node=node)

    def visit_importfrom(self, node):
        if node.modname == 'os' or node.modname.startswith('os.') and not _check_disabled(node):
            self.add_message('os-module-forbidden', node=node)


def register(linter):
    """Pylint hook to auto-register this linter"""
    linter.register_checker(ForbidStandardOsModule(linter))


def _check_disabled(node):
    module = node.root()
    return any(path for path in WHITELIST_PATHS
               if os.path.normpath(path) in os.path.normpath(module.file))

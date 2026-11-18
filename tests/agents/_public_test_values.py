"""Adversarial primitive values shared by public test modules."""


class ForgedString(str):
    """Record caller hooks reached before exact primitive validation."""

    def __new__(cls, value):
        instance = str.__new__(cls, value)
        instance.hooks = []
        return instance

    def __eq__(self, other):
        self.hooks.append("equality")
        return True

    def __ne__(self, other):
        self.hooks.append("inequality")
        return False

    def __hash__(self):
        self.hooks.append("hash")
        return str.__hash__(self)

    def startswith(self, *args):
        self.hooks.append("prefix")
        return True

    def __getitem__(self, key):
        self.hooks.append("slice")
        return str.__getitem__(self, key)

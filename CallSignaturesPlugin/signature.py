import os
import yaml
import logging

import idaapi

import FIDL.decompiler_utils

from CallSignaturesPlugin.rule import Rule


class Call:
    """
    A wrapper class around the IDA Pro API libraries.

    This class also acts as an abstraction layer. If the IDA Pro API (or the way we interface with the API) changes,
    only this class needs to be changed.
    """

    def __init__(self, call: FIDL.decompiler_utils.callObj):
        """Extract the necessary information from a function call found by IDA Pro."""
        self.address = call.ea

        if not call.name.startswith("sub_"):
            self.function_name = call.name
        else:
            self.function_name = None

        self.number_of_arguments = len(call.args)

        self.arguments = []
        for i in range(len(call.args)):

            argument = call.args[i]
            if argument.type == "string":
                value = call.args[i].val

            # Only use the first 32 bits of numbers
            elif argument.type == "number":
                value = 0xFFFFFFFF & argument.val

            elif argument.type == "global":
                try:
                    value = self._get_global_string(argument.val)
                except ValueError:
                    value = None

            elif argument.type == "ref":
                argument_flags = idaapi.get_flags(argument.val.obj_ea)
                argument_size = idaapi.get_data_elsize(
                    argument.val.obj_ea, argument_flags
                )
                value = idaapi.get_bytes(argument.val.obj_ea, argument_size)

            elif argument.type == "unk" and argument.val.string is not None:
                value = argument.val.string

            else:
                value = None

            self.arguments.append(value)

    @staticmethod
    def _get_global_string(str_ea):
        """
        Try to dereference a string from an address to global variable.

        Taken from FIDL 'string_value' function
        """
        str_type = idaapi.get_str_type(str_ea) & 0xF
        str_b = idaapi.get_strlit_contents(str_ea, -1, str_type)

        if str_b is None:
            raise ValueError

        return str_b.decode("utf-8")

    def __str__(self) -> str:
        """Represent a rule as a string."""
        argument_string = ""
        for argument in self.arguments:
            argument_type = Rule._get_type(argument)

            if argument_type == Rule.Type.STRING:
                argument_string += f"'{argument}'"

            elif argument_type == Rule.Type.NUMBER:
                argument_string += str(hex(argument))

            elif argument_type == Rule.Type.BYTES:
                argument_string += f"0x{argument.hex()}"

            else:
                argument_string += "?"

            argument_string += ", "
        argument_string = argument_string[:-2]

        return f"{self.function_name or '?'}({argument_string})"


class Signature:
    """A Call Signature."""

    def __init__(self, path: str):
        """Parse a YAML file into a Call Signature."""
        self.logger = logging.getLogger(__name__)

        self.path = path
        self.filename = os.path.basename(path)

        self.logger.info(f"Loading signature at '{self.path}'")
        with open(self.path) as h_yaml:
            self._data = yaml.safe_load(h_yaml)["signature"]

        self.technique = self._data["technique"]
        self.description = self._data.get("description", "")

        self.rules = []
        for rule_yaml in self._data["rules"]:
            self.rules.append(Rule(rule_yaml))

    def match(self, call: Call) -> bool:
        """Iterate through the rules and compare each one with a call."""
        for rule in self.rules:

            if rule.element == "function name":
                result = rule.match(call.function_name)

            elif rule.element == "number of arguments":
                result = rule.match(call.number_of_arguments)

            elif rule.element == "argument":
                if rule.argument_index < call.number_of_arguments:
                    result = rule.match(call.arguments[rule.argument_index])
                else:
                    result = False

            elif rule.element == "any argument":
                result = False
                for argument in call.arguments:
                    if rule.match(argument):
                        result = True
                        break

            else:
                raise ValueError(f"Unknown name: {rule.element}")

            self.logger.debug(f"{str(call)}: {str(rule)} -> {result}")

            if not result:
                return False

        return True

    def __str__(self):
        """Represent the Call Signature as a list of rules."""
        return f"{self.technique}: {' and '.join(str(rule) for rule in self.rules)}"

    @staticmethod
    def read_signatures(path):
        """Find all YAML files and parse them into Call Signature objects."""
        signatures = []
        for subdirectory_path, _, filenames in os.walk(path):
            for filename in filenames:

                if filename.endswith(".yaml") or filename.endswith(".yml"):
                    signatures.append(
                        Signature(os.path.join(subdirectory_path, filename))
                    )
        return signatures

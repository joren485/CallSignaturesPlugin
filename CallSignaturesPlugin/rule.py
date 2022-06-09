from enum import Enum

from typing import List


class Rule:
    """An object representing one rule in a Call Signature."""

    OPERATORS = ("true", "equals", "contains", "contains_in", "in")

    class Type(Enum):
        """The type of data used in the rule."""

        UNKNOWN = "unknown"
        STRING = "string"
        NUMBER = "number"
        BYTES = "bytes"

        @classmethod
        def _missing_(cls, key):
            return cls.UNKNOWN

        def __str__(self):
            """Use the value of a type as its string representation."""
            return self.value

    def __init__(self, yaml_data: dict):
        """Parse the YAML data from the Call Signature file into a rule."""
        self.element = yaml_data["element"]

        if self.element.startswith("argument"):
            self.argument_index = int(yaml_data["argument_index"])

        self.operator, self.value = self._get_operator(yaml_data)

        if "type" in yaml_data:
            self.type = Rule.Type(yaml_data["type"])
        else:
            self.type = self._get_type(self.value)

        if self.type == Rule.Type.BYTES:
            if isinstance(self.value, list):
                self.value = [bytes.fromhex(e) for e in self.value]
            if isinstance(self.value, str):
                self.value = bytes.fromhex(self.value)

    def __str__(self):
        """Represent the rule as string."""
        if self.value:
            operator = self.operator.__name__[1:]
            return f"[{self.element} {operator} '{self.value}' ({self.type})]"

        return f"[{self.element} is of type {self.type}]"

    def _get_operator(self, yaml_data: dict):
        """Find the operator in the YAML rule data."""
        for key in yaml_data:
            if key in self.OPERATORS:
                value = yaml_data[key]
                return getattr(self, f"_{key}"), value

        return self._true, None

    @staticmethod
    def _get_type(data):
        """Deduce the type of data."""
        if data is None:
            return Rule.Type.UNKNOWN

        elif isinstance(data, str):
            return Rule.Type.STRING

        elif isinstance(data, int):
            return Rule.Type.NUMBER

        elif isinstance(data, bytes):
            return Rule.Type.BYTES

        elif isinstance(data, list) and len(data) > 0:
            return Rule._get_type(data[0])

        return Rule.Type.UNKNOWN

    def match(self, other) -> bool:
        """
        Compare the rule to a value.

        If the other value in the rule is unknown and the rule applies to function names,
        the result is considered a match.

        First check if the types match and if they do, check if the values match (using the rule operator).
        """
        other_type = self._get_type(other)

        if other_type == Rule.Type.UNKNOWN and self.element in ("function name",):
            return True

        return other_type == self.type and self.operator(self.value, other)

    # Operators

    @staticmethod
    def _true(*_) -> bool:
        """Return true."""
        return True

    @staticmethod
    def _equals(value, other) -> bool:
        """
        Check whether `value` and `other` are equal.

        Strings comparisons are case-insensitive.
        """
        if isinstance(value, str) and isinstance(other, str):
            return value.casefold() == other.casefold()

        return value == other

    @staticmethod
    def _contains(value: str, other: str) -> bool:
        """Check whether `value` is a substring of `other`."""
        if not isinstance(value, str) or not isinstance(other, str):
            return False

        return value.casefold() in other.casefold()

    @staticmethod
    def _in(values: List, other):
        """
        Check whether `other` is an element of `values`.

        This function uses the in operator for the comparison of two values.
        """
        if not isinstance(values, list):
            return False

        for value in values:
            if Rule._equals(value, other):
                return True

        return False

    @staticmethod
    def _contains_in(values: List[str], other: str):
        """
        Check whether a string element of `values` is a substring of `other`.

        This function uses the contains operator for the string comparison.
        """
        if not isinstance(values, list):
            return False

        for value in values:
            if Rule._contains(value, other):
                return True

        return False

import os
import logging

import idaapi
import idautils
import idc

import FIDL.decompiler_utils as du

from CallSignaturesPlugin.signature import Signature, Call
from CallSignaturesPlugin.form import CallSignaturesChoose


class CallSignaturesPlugin(idaapi.plugin_t):
    """An IDA Pro plugin that searches for function calls."""

    PLUGIN_NAME = "CallSignaturesPlugin"

    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Alt-Shift-D"
    flags = idaapi.PLUGIN_UNL

    comment = ""
    help = ""

    def __init__(self):
        """
        Initialize CallSignaturesPlugin object.

        As the actual initialization is done when IDA Pro calls the init method,
        only some variables are declared.
        """
        super().__init__()

        logging.basicConfig(
            format=f"[%(asctime)s] {CallSignaturesPlugin.PLUGIN_NAME}: %(message)s",
            datefmt="%H:%M:%S",
        )
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        self.signatures = []
        self.chooser_tab = None

    def init(self):
        """
        Initialize the plugin by reading the Call Signature YAML files and opening a tab.

        This method is run when IDA Pro loads all plugins.
        """
        self.logger.debug(f"Initializing")

        signatures_path = os.path.join(
            idaapi.get_user_idadir(),
            "plugins",
            CallSignaturesPlugin.PLUGIN_NAME,
            "signatures",
        )
        self.signatures = Signature.read_signatures(signatures_path)

        self.chooser_tab = CallSignaturesChoose(CallSignaturesPlugin.PLUGIN_NAME)
        self.chooser_tab.Show()

        return idaapi.PLUGIN_OK

    def run(self, args):
        """
        Run the matching logic.

        1. Decompile all functions.
        2. Find all calls in a (decompiled) function.
        3. Check whether a function matches a Call Signature.
        """
        self.logger.debug("Running")
        for ea in idautils.Functions():

            name = idaapi.get_name(ea)

            # Skip library functions (FUNC_LIB) and dynamically linked functions (FUNC_THUNK)
            if idc.get_func_flags(ea) & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK):
                continue

            self.logger.debug(f"Decompiling function: {name}")

            try:
                c = du.controlFlowinator(ea)
            except (RuntimeError, IndexError):
                self.logger.warning(f"Failed to decompile: {name}")
                continue

            for call_object in c.calls:
                call = Call(call_object)

                for signature in self.signatures:
                    if signature.match(call):
                        self.chooser_tab.add_item(call, signature)
                        self.logger.info(f"MATCH: [{signature.filename}] {str(call)}")

    def term(self):
        """
        Terminate the plugin.

        This method is required.
        """
        self.logger.debug("Terminating")


def PLUGIN_ENTRY() -> CallSignaturesPlugin:
    """IDA Pro calls this function when the plugin is run."""
    return CallSignaturesPlugin()

import idc

from idaapi import Choose


class CallSignaturesChoose(Choose):
    """
    An object that creates a new tabular tab for the Call Signature results.

    A Choose object creates a new tab in IDA Pro to show data in a tabular format.
    The Imports tab is an example of a Choose object.
    """

    def __init__(self, title):
        """
        Pass the title and the header to the parent constructor.

        1. The first argument is the title as a string.
        2. The second argument is a list headers.
          Each element contains the name of the header
          and a combination of the position (e.g. 10) and the type (e.g. CHCOL_HEX).
        3. The CH_CAN_REFRESH flags argument specifies that the tab data can be refreshed.
          This is necessary to add data dynamically.
        """
        super().__init__(
            title,
            [
                ["Address", 10 | Choose.CHCOL_HEX],
                ["Technique", 20 | Choose.CHCOL_PLAIN],
                ["Call", 30 | Choose.CHCOL_PLAIN],
                ["Call Signature", 40 | Choose.CHCOL_PLAIN],
            ],
            flags=Choose.CH_CAN_REFRESH,
        )

        self.items = []

    def OnGetSize(self):
        """Return the number of lines."""
        return len(self.items)

    def OnGetLine(self, n):
        """Return the data of a line."""
        return self.items[n]

    def OnSelectLine(self, n):
        """Jump to the function call in the IDA view tab."""
        idc.jumpto(int(self.items[n][0], 16))
        return (Choose.NOTHING_CHANGED,)

    def OnRefresh(self, n):
        """
        1Signify that a refresh should happen.

        This method is necessary for the refresh to be enabled.
        """
        return None

    def add_item(self, call, signature):
        """
        Add a line to the tab.

        Each line represents a match of a function call and a Call Signature. They consist of:
        1. The address (in hex) of the function call.
        2. The technique code that is matched.
        3. The decompiled call (including arguments).
        4. The Call Signature file

        After the line is added, refresh the tab to make the new line visible.
        """
        self.items.append(
            (hex(call.address), signature.technique, str(call), signature.filename)
        )
        self.Refresh()

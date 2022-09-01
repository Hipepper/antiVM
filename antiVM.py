import idaapi
import idautils
import ida_bytes
import idc
import ida_kernwin
import yara
import string
import os

from tkinter import messagebox

PLUGIN_NAME = "antiVM"
PLUGIN_HOTKEY = "Ctrl-Alt-A"
VERSION = '1.0.0'
globalRuleFile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antiVM.rules")
# globalRuleFile = "antiVM.rules"

try:
    class Kp_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)


        @classmethod
        def get_name(self):
            return self.__name__


        @classmethod
        def get_label(self):
            return self.label


        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))


        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())


        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1


        @classmethod
        def update(self, ctx):
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET


    class Searcher(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search()
            return 1

except:
    pass

p_initialized = False



class YaraSearchResultChooser(idaapi.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose.__init__(
            self,
            title,
            [
                ["Address", idaapi.Choose.CHCOL_HEX|10],
                ["Rule Name", idaapi.Choose.CHCOL_PLAIN|20],
                ["Match Name", idaapi.Choose.CHCOL_PLAIN|20],
                ["Match", idaapi.Choose.CHCOL_PLAIN|40],
                ["Type", idaapi.Choose.CHCOL_PLAIN|10],
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)


    def OnClose(self):
        return


    def OnSelectLine(self, n):
        self.selcount += 1
        ida_kernwin.jumpto(self.items[n][0])


    def OnGetLine(self, n):
        res = self.items[n]
        res = [idc.atoa(res[0]), res[1], res[2], res[3], res[4]]
        return res


    def OnGetSize(self):
        n = len(self.items)
        return n


    def show(self):
        return self.Show() >= 0

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class antiVM_Plugin_t(idaapi.plugin_t):
    comment = "antiVM plugin for IDA Pro (using yara framework)"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    flags = idaapi.PLUGIN_KEEP


    def init(self):
        global p_initialized

        # register popup menu handlers
        try:
            Searcher.register(self, "antiVM")
        except:
            pass

        if p_initialized is False:
            p_initialized = True
            idaapi.register_action(idaapi.action_desc_t(
                "antiVM",
                "Find antiVM rule matches!",
                self.search,
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Edit/antiVM", "antiVM", idaapi.SETMENU_APP)
            print("=" * 80)
            print(r"              _   ___      ____  __ ")
            print(r"             | | (_) \    / /  \/  |")
            print(r"   __ _ _ __ | |_ _ \ \  / /| \  / |")
            print(r"  / _` | '_ \| __| | \ \/ / | |\/| |")
            print(r" | (_| | | | | |_| |  \  /  | |  | |")
            print(r"  \__,_|_| |_|\__|_|   \/   |_|  |_|")
            print("=" * 80)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass


    def toVirtualAddress(self, offset, segments):
        va_offset = 0
        for seg in segments:
            if seg[1] <= offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset


    def search(self, yara_file):
        memory, offsets = self.get_memory()
        try:
            rules = yara.compile(yara_file)
        except:
            print("ERROR: Cannot compile Yara rules from %s" % yara_file)
            return
        values = self.yarasearch(memory, offsets, rules)
        c = YaraSearchResultChooser("antiVM results", values)
        r = c.show()
        title = "antiVM result"
        message = "antiVM rules path:" + str(globalRuleFile) + "\n"
        message += "find anti nums:" + str(len(values))
        messagebox.showinfo(title,message)


    def yarasearch(self, memory, offsets, rules):
        values = list()
        matches = rules.match(data=memory)
        for rule_match in matches:
            name = rule_match.rule
            for match in rule_match.strings:
                match_string = match[2]
                match_type = 'unknown'
                if all(chr(c) in string.printable for c in match_string):
                    match_string = match_string.decode('utf-8')
                    match_type = 'ascii string'
                elif all(chr(c) in string.printable+'\x00' for c in match_string) and (b'\x00\x00' not in match_string):
                     match_string = match_string.decode('utf-16')
                     match_type = 'wide string'
                else:
                    match_string = " ".join("{:02x}".format(c) for c in match_string)
                    match_type = 'binary'

                value = [
                    self.toVirtualAddress(match[0], offsets),
                    name,
                    match[1],
                    match_string,
                    match_type
                ]
                values.append(value)
        return values


    def get_memory(self):
        result = bytearray()
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.get_segm_attr(start, idc.SEGATTR_END)
            result += ida_bytes.get_bytes(start, end - start)
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return bytes(result), offsets


    def run(self, arg):
        if os.path.exists(globalRuleFile) != True:
            print("ERROR: can not find antiVM.rules in the root path!!")
            exit()
        print("antiVM INFO:",globalRuleFile)
        yara_file = globalRuleFile
        self.search(yara_file)


# register IDA plugin
def PLUGIN_ENTRY():
    return antiVM_Plugin_t()

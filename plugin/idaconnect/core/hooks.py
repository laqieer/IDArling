import logging

import ida_idp
import idaapi
import idc

from events import *
from ..utilities.misc import DictDiffer

logger = logging.getLogger('IDAConnect.Core')


class Hooks(object):
    """
    This is the base class for every hook of the core module.
    """

    def __init__(self, plugin):
        """
        Initialize the hook.

        :param plugin: the plugin instance
        """
        self._plugin = plugin

    def _sendEvent(self, event):
        """
        Send an event to the other clients through the server.

        :param event: the event to send
        """
        self._plugin.network.sendPacket(event)


class IDBHooks(Hooks, ida_idp.IDB_Hooks):
    """
    The concrete class for all IDB-related events.
    """

    def __init__(self, plugin):
        ida_idp.IDB_Hooks.__init__(self)
        Hooks.__init__(self, plugin)

    def make_code(self, insn):
        self._sendEvent(MakeCodeEvent(insn.ea))
        return 0

    def make_data(self, ea, flags, tid, size):
        self._sendEvent(MakeDataEvent(ea, flags, size, tid))
        return 0

    def renamed(self, ea, new_name, local_name):
        self._sendEvent(RenamedEvent(ea, new_name, local_name))
        return 0

    def func_added(self, func):
        self._sendEvent(FuncAddedEvent(func.startEA, func.endEA))
        return 0

    def deleting_func(self, func):
        self._sendEvent(DeletingFuncEvent(func.startEA))
        return 0

    def set_func_start(self, func, new_start):
        self._sendEvent(SetFuncStartEvent(func.startEA, new_start))
        return 0

    def set_func_end(self, func, new_end):
        self._sendEvent(SetFuncEndEvent(func.startEA, new_end))
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        cmt = idc.get_cmt(ea, repeatable_cmt)
        cmt = '' if not cmt else cmt
        self._sendEvent(CmtChangedEvent(ea, cmt, repeatable_cmt))
        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        self._sendEvent(ExtraCmtChangedEvent(ea, line_idx, cmt))
        return 0

    def ti_changed(self, ea, type, fname):
        type = idc.GetTinfo(ea)
        self._sendEvent(TiChangedEvent(ea, type))
        return 0

    def op_type_changed(self, ea, n):
        def gather_enum_info(ea, n):
            id = idaapi.get_enum_id(ea, n)[0]
            serial = idaapi.get_enum_idx(id)
            return id, serial

        extra = {}
        flags = idc.get_full_flags(ea)
        if n == 0:
            if idc.isHex0(flags):
                op = 'hex'
            elif idc.isBin0(flags):
                op = 'bin'
            elif idc.isDec0(flags):
                op = 'dec'
            elif idc.isChar0(flags):
                op = 'chr'
            elif idc.isOct0(flags):
                op = 'oct'
            elif idc.isEnum0(flags):
                op = 'enum'
                id, serial = gather_enum_info(ea, n)
                extra['id'] = id
                extra['serial'] = serial
            else:
                # FIXME: Find a better way
                return 0
        else:
            if idc.isHex1(flags):
                op = 'hex'
            elif idc.isBin1(flags):
                op = 'bin'
            elif idc.isDec1(flags):
                op = 'dec'
            elif idc.isChar1(flags):
                op = 'chr'
            elif idc.isOct1(flags):
                op = 'oct'
            elif idc.isEnum1(flags):
                op = 'enum'
                id, serial = gather_enum_info(ea, n)
                extra['id'] = id
                extra['serial'] = serial
            else:
                # FIXME: Find a better way
                return 0
        self._sendEvent(OpTypeChangedEvent(ea, n, op, extra))
        return 0

    def enum_created(self, enum):
        name = idc.get_enum_name(enum)
        self._sendEvent(EnumCreatedEvent(enum, name))
        return 0

    def enum_deleted(self, enum):
        self._sendEvent(EnumDeletedEvent(enum))
        return 0

    def enum_renamed(self, tid):
        new_name = idaapi.get_enum_name(tid)
        self._sendEvent(EnumRenamedEvent(tid, new_name))
        return 0

    def enum_bf_changed(self, tid):
        bf_flag = 1 if idc.IsBitfield(tid) else 0
        self._sendEvent(EnumBfChangedEvent(tid, bf_flag))
        return 0

    def enum_cmt_changed(self, tid, repeatable_cmt):
        cmt = idaapi.get_enum_cmt(tid, repeatable_cmt)
        self._sendEvent(EnumCmtChangedEvent(tid, cmt, repeatable_cmt))
        return 0

    def enum_member_created(self, id, cid):
        name = idaapi.get_enum_member_name(cid)
        value = idaapi.get_enum_member_value(cid)
        bmask = idaapi.get_enum_member_bmask(cid)
        self._sendEvent(EnumMemberCreatedEvent(id, name, value, bmask))
        return 0

    def enum_member_deleted(self, id, cid):
        value = idaapi.get_enum_member_value(cid)
        serial = idaapi.get_enum_member_serial(cid)
        bmask = idaapi.get_enum_member_bmask(cid)
        self._sendEvent(EnumMemberDeletedEvent(id, value, serial, bmask))
        return 0

    def struc_created(self, tid):
        name = idaapi.get_struc_name(tid)
        is_union = idaapi.is_union(tid)
        self._sendEvent(StrucCreatedEvent(tid, name, is_union))
        return 0

    def struc_deleted(self, tid):
        self._sendEvent(StrucDeletedEvent(tid))
        return 0

    def struc_renamed(self, sptr):
        new_name = idaapi.get_struc_name(sptr.id)
        self._sendEvent(StrucRenamedEvent(sptr.id, new_name))
        return 0

    def struc_member_created(self, sptr, mptr):
        extra = {}

        fieldname = idaapi.get_member_name2(mptr.id)
        offset = 0 if mptr.unimem() else mptr.soff
        flag = mptr.flag
        nbytes = mptr.eoff if mptr.unimem() else mptr.eoff - mptr.soff
        mt = idaapi.opinfo_t()
        is_not_data = idaapi.retrieve_member_info(mt, mptr)
        if is_not_data:
            if idaapi.isOff0(flag) or idaapi.isOff1(flag):
                extra['target'] = mt.ri.target
                extra['base'] = mt.ri.base
                extra['tdelta'] = mt.ri.tdelta
                extra['flags'] = mt.ri.flags
                self._sendEvent(StrucMemberCreatedEvent(sptr.id, fieldname,
                                                        offset, flag, nbytes,
                                                        extra))
            # Is it really possible to create an enum?
            elif idaapi.isEnum0(flag):
                extra['serial'] = mt.ec.serial
                self._sendEvent(StrucMemberCreatedEvent(sptr.id, fieldname,
                                                        offset, flag, nbytes,
                                                        extra))
            elif idaapi.isStruct(flag):
                extra['id'] = mt.tid
                self._sendEvent(StrucMemberCreatedEvent(sptr.id, fieldname,
                                                        offset, flag, nbytes,
                                                        extra))
            elif idaapi.isASCII(flag):
                extra['strtype'] = mt.strtype
                self._sendEvent(StrucMemberCreatedEvent(sptr.id, fieldname,
                                                        offset, flag, nbytes,
                                                        extra))
        else:
            self._sendEvent(StrucMemberCreatedEvent(sptr.id, fieldname,
                                                    offset, flag, nbytes,
                                                    extra))
        return 0

    def struc_member_deleted(self, sptr, off1, off2):
        self._sendEvent(StrucMemberDeletedEvent(sptr.id, off2))
        return 0

    def struc_member_changed(self, sptr, mptr):
        extra = {}

        soff = 0 if mptr.unimem() else mptr.soff
        flag = mptr.flag
        mt = idaapi.opinfo_t()
        is_not_data = idaapi.retrieve_member_info(mt, mptr)
        if is_not_data:
            if idaapi.isOff0(flag) or idaapi.isOff1(flag):
                extra['target'] = mt.ri.target
                extra['base'] = mt.ri.base
                extra['tdelta'] = mt.ri.tdelta
                extra['flags'] = mt.ri.flags
                self._sendEvent(StrucMemberChangedEvent(sptr.id, soff,
                                                        mptr.eoff, flag,
                                                        extra))
            # Is it really possible to create an enum?
            elif idaapi.isEnum0(flag):
                extra['serial'] = mt.ec.serial
                self._sendEvent(StrucMemberChangedEvent(sptr.id, soff,
                                                        mptr.eoff, flag,
                                                        extra))
            elif idaapi.isStruct(flag):
                extra['id'] = mt.tid
                self._sendEvent(StrucMemberChangedEvent(sptr.id, soff,
                                                        mptr.eoff, flag,
                                                        extra))
            elif idaapi.isASCII(flag):
                extra['strtype'] = mt.strtype
                self._sendEvent(StrucMemberChangedEvent(sptr.id, soff,
                                                        mptr.eoff, flag,
                                                        extra))
        else:
            self._sendEvent(StrucMemberChangedEvent(sptr.id, soff,
                                                    mptr.eoff, flag,
                                                    extra))
        return 0

    def struc_cmt_changed(self, tid, repeatable_cmt):
        cmt = idaapi.get_struc_cmt(tid, repeatable_cmt)
        self._sendEvent(StrucCmtChangedEvent(tid, cmt, repeatable_cmt))
        return 0

    def expanding_struc(self, sptr, offset, delta):
        self._sendEvent(ExpandingStrucEvent(sptr.id, offset, delta))
        return 0

    def segm_added(self, s):
        self._sendEvent(SegmAddedEvent(idaapi.get_segm_name(s),
                                       idaapi.get_segm_class(s),
                                       s.start_ea, s.end_ea,
                                       s.orgbase, s.align, s.comb,
                                       s.perm, s.bitness, s.flags))
        return 0

    def segm_deleted(self, start_ea, end_ea):
        self._sendEvent(SegmDeletedEvent(start_ea))
        return 0

    def segm_start_changed(self, s, oldstart):
        self._sendEvent(SegmStartChangedEvent(s.start_ea, oldstart))
        return 0

    def segm_end_changed(self, s, oldend):
        self._sendEvent(SegmEndChangedEvent(s.end_ea, s.start_ea))
        return 0

    def segm_name_changed(self, s, name):
        self._sendEvent(SegmNameChangedEvent(s.start_ea, name))
        return 0

    def segm_class_changed(self, s, sclass):
        self._sendEvent(SegmClassChangedEvent(s.start_ea, sclass))
        return 0


class IDPHooks(Hooks, ida_idp.IDP_Hooks):
    """
    The concrete class for IDP-related events.
    """

    def __init__(self, plugin):
        ida_idp.IDP_Hooks.__init__(self)
        Hooks.__init__(self, plugin)

    def ev_undefine(self, ea):
        self._sendEvent(UndefinedEvent(ea))
        return 0

    def ev_adjust_argloc(self, *_):
        return 0


class HexRaysHooks(Hooks):
    """
    The concrete class for Hex-Rays-related events.
    """

    def __init__(self, plugin):
        super(HexRaysHooks, self).__init__(plugin)
        self._available = None
        self._installed = False
        self._func = None
        self._labels = {}
        self._cmts = {}
        self._iflags = {}

    def hook(self):
        if self._available is None:
            if not idaapi.init_hexrays_plugin():
                logger.info("Hex-Rays SDK is not available")
                self._available = False
            else:
                idaapi.install_hexrays_callback(self._hxe_callback)
                self._available = True

        if self._available:
            self._installed = True

    def unhook(self):
        if self._available:
            self._installed = False

    def _hxe_callback(self, event, *_):
        if not self._installed:
            return 0

        if event == idaapi.hxe_func_printed:
            ea = idaapi.get_screen_ea()
            func = idaapi.get_func(ea)
            if self._func and self._func.startEA != func.startEA:
                self._cmts = {}
            self._func = func
            self._getUserLabels(func.startEA)
            self._getUserCmts(func.startEA)
            self._getUserIflags(func.startEA)
        return 0

    def _getUserLabels(self, ea):
        user_labels = idaapi.restore_user_labels(ea)
        if user_labels is None:
            user_labels = idaapi.user_labels_new()
        labels = {}
        it = idaapi.user_labels_begin(user_labels)
        while it != idaapi.user_labels_end(user_labels):
            org_label = idaapi.user_labels_first(it)
            name = idaapi.user_labels_second(it)
            labels[org_label] = name
            it = idaapi.user_labels_next(it)
        diff = DictDiffer(labels, self._labels)
        for org_label in diff.added():
            self._sendEvent(
                UserDefinedLabelEvent(ea, org_label, labels[org_label]))
        for org_label in diff.removed():
            self._sendEvent(UserErasedLabelEvent(ea, org_label))
        for org_label in diff.changed():
            self._sendEvent(
                UserModifiedLabelEvent(ea, org_label, labels[org_label]))
        self._labels = labels
        idaapi.user_labels_free(user_labels)

    def _getUserCmts(self, ea):
        user_cmts = idaapi.restore_user_cmts(ea)
        if user_cmts is None:
            user_cmts = idaapi.user_cmts_new()
        cmts = {}
        it = idaapi.user_cmts_begin(user_cmts)
        while it != idaapi.user_cmts_end(user_cmts):
            tl = idaapi.user_cmts_first(it)
            cmt = idaapi.user_cmts_second(it)
            cmts[(tl.ea, tl.itp)] = str(cmt)
            it = idaapi.user_cmts_next(it)
        diff = DictDiffer(cmts, self._cmts)
        for ea, itp in diff.added():
            self._sendEvent(UserDefinedCmtEvent(ea, itp, cmts[(ea, itp)]))
        for ea, itp in diff.removed():
            self._sendEvent(UserDefinedCmtEvent(ea, itp, ''))
        for ea, itp in diff.changed():
            self._sendEvent(UserDefinedCmtEvent(ea, itp, cmts[(ea, itp)]))
        self._cmts = cmts
        idaapi.user_cmts_free(user_cmts)

    def _getUserIflags(self, ea):
        user_iflags = idaapi.restore_user_iflags(ea)
        if user_iflags is None:
            user_iflags = idaapi.user_iflags_new()
        iflags = {}
        it = idaapi.user_iflags_begin(user_iflags)
        while it != idaapi.user_iflags_end(user_iflags):
            cl = idaapi.user_iflags_first(it)
            f = idaapi.user_iflags_second(it)

            # Temporary fix while Hex-Rays fix their API
            def read_type_sign(obj):
                import ctypes
                import struct
                buf = ctypes.string_at(id(obj), 4)
                return struct.unpack('I', buf)[0]
            f = read_type_sign(f)
            iflags[(cl.ea, cl.op)] = f
            it = idaapi.user_iflags_next(it)
        diff = DictDiffer(iflags, self._iflags)
        for cl_ea, cl_op in diff.added():
            self._sendEvent(UserDefinedIflagsEvent(ea, cl_ea, cl_op,
                                                   iflags[(cl_ea, cl_op)]))
        for cl_ea, cl_op in diff.removed():
            self._sendEvent(UserDefinedIflagsEvent(ea, cl_ea, cl_op, 0))
        for cl_ea, cl_op in diff.changed():
            self._sendEvent(UserDefinedIflagsEvent(ea, cl_ea, cl_op,
                                                   iflags[(cl_ea, cl_op)]))
        self._iflags = iflags
        idaapi.user_iflags_free(user_iflags)

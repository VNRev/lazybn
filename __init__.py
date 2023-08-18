from struct import unpack

# capstone/keystone stuff
# binaryninja
# Qt stuff
# capstone/keystone stuff
# binaryninja
import pyperclip
# Qt stuff
from binaryninja import *


def u16(x): return unpack("<H", x)[0]


def u32(x): return unpack("<I", x)[0]


def u64(x): return unpack("<Q", x)[0]


def toDouble(x): return unpack("d", x)[0]


def toFloat(x): return unpack("f", x)[0]


def do_nothing(bv: BinaryView):
    show_message_box("Do Nothing", "Congratulations! You have successfully done nothing.\n\n" +
                     "Pat yourself on the back.", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


def preProcess(bv: BinaryView, start: int, size: int):
    # print("startAddr:0x%x,length:0x%x" % (start, size))
    end = start + size
    selectRange = (start, end)
    # print("selectRange:0x%x,0x%x" % (selectRange[0], selectRange[1]))
    data = bv.read(selectRange[0], size)
    if data:
        print("\n[+] Dump 0x%X - 0x%X (%u bytes) :" %
              (start, end, size))
        return data
    return b''


def convert2EscapedString(bv: BinaryView, start: int, size: int):
    """
    \x11\x31\xf1
    """
    data = preProcess(bv, start, size)
    output = '"%s"' % "".join("\\x%02X" % b for b in data)
    print(output)
    pyperclip.copy(output)


def convert2Hex(bv: BinaryView, start: int, size: int):
    """
    11ff2233dfe1
    """
    data = preProcess(bv, start, size)
    # hex string
    output = "".join("%02X" % b for b in data)
    print(output)
    pyperclip.copy(output)


def convert2C_uint8_t(bv: BinaryView, start: int, size: int):
    """
    Convert to C string
    unsigned char data_434869[31] = {
    0x48, 0x8B, 0x89, 0x00, 0x00, 0x00, 0x00, 0x48, 0x3B, 0x61, 0x10, 0x0F, 0x86, 0x34, 0x03, 0x00,
    0x00, 0x48, 0x83, 0xEC, 0x50, 0x48, 0x89, 0x6C, 0x24, 0x48, 0x48, 0x8D, 0x6C, 0x24, 0x48
};
    """
    data = preProcess(bv, start, size)
    try:
        name = bv.get_data_var_at(start).name
        assert name
    except:
        name = "data_%X" % start
    output = "uint8_t %s[%d] = {" % (name, size)
    for i in range(size):
        if i % 16 == 0:
            output += "\n    "
        output += "0x%02X, " % data[i]
    output = output[:-2] + "\n};"
    print(output)
    pyperclip.copy(output)


def convert2C_uint16_t(bv: BinaryView, start: int, size: int):
    data = preProcess(bv, start, size)
    try:
        name = bv.get_data_var_at(start).name
        assert name
    except:
        name = "data_%X" % start
    data += b"\x00"
    array_size = (size + 1) // 2
    output = "uint16_t %s[%d] = {" % (name, array_size)
    for i in range(0, size, 2):
        if i % 16 == 0:
            output += "\n    "
        output += "0x%04X, " % u16(data[i:i + 2])
    output = output[:-2] + "\n};"
    print(output)
    pyperclip.copy(output)


def convert2C_uint32_t(bv: BinaryView, start: int, size: int):
    data = preProcess(bv, start, size)
    try:
        name = bv.get_data_var_at(start).name
        assert name
    except:
        name = "data_%X" % start
    # C array dword
    data += b"\x00" * 3
    array_size = (size + 3) // 4
    output = "uint32_t %s[%d] = {" % (name, array_size)
    for i in range(0, size, 4):
        if i % 32 == 0:
            output += "\n    "
        output += "0x%08X, " % u32(data[i:i + 4])
    output = output[:-2] + "\n};"
    print(output)
    pyperclip.copy(output)


def convert2C_uint64_t(bv: BinaryView, start: int, size: int):
    data = preProcess(bv, start, size)
    try:
        name = bv.get_data_var_at(start).name
        assert name
    except:
        name = "data_%X" % start
    # C array qword
    data += b"\x00" * 7
    array_size = (size + 7) // 8
    output = "uint64_t %s[%d] = {" % (name, array_size)
    for i in range(0, size, 8):
        if i % 32 == 0:
            output += "\n    "
        output += "%#018X, " % u64(data[i:i + 8])
    output = output[:-2] + "\n};"
    output = output.replace("0X", "0x")
    print(output)
    pyperclip.copy(output)


def convert2Puint8_t(bv: BinaryView, start: int, size: int):
    data = preProcess(bv, start, size)
    # python list
    output = "[%s]" % ", ".join("0x%02X" % b for b in data)
    print(output)
    pyperclip.copy(output)


def convert2Puint16_t(bv: BinaryView, start: int, size: int):
    data = preProcess(bv, start, size)
    # python list word
    data += b"\x00"
    output = "[%s]" % ", ".join("0x%04X" % u16(data[i:i + 2])
                                for i in range(0, size, 2))
    print(output)
    pyperclip.copy(output)


def convert2Puint32_t(bv: BinaryView, start: int, size: int):
    data = preProcess(bv, start, size)
    # python list dword
    data += b"\x00" * 3
    output = "[%s]" % ", ".join("0x%08X" % u32(data[i:i + 4])
                                for i in range(0, size, 4))
    print(output)
    pyperclip.copy(output)


def convert2Puint64_t(bv: BinaryView, start: int, size: int):
    data = preProcess(bv, start, size)
    # python list qword
    data += b"\x00" * 7
    output = "[%s]" % ", ".join("%#018X" % u64(data[i:i + 8]) for i in range(0, size, 8)).replace("0X",
                                                                                                  "0x")
    print(output)
    pyperclip.copy(output)


def convert2Pdouble(bv: BinaryView, start: int, size: int):
    data = preProcess(bv, start, size)
    # python list double
    data += b"\x00" * 7
    output = "[%s]" % ", ".join("%.10f" % toDouble(data[i:i + 8]) for i in range(0, size, 8))
    print(output)
    pyperclip.copy(output)


def convert2Pfloat(bv: BinaryView, start: int, size: int):
    data = preProcess(bv, start, size)
    # python list float
    data += b"\x00" * 3
    output = "[%s]" % ", ".join("%.10f" % toFloat(data[i:i + 4]) for i in range(0, size, 4))
    print(output)
    pyperclip.copy(output)


def getNop(arch):
    if arch in ['x16', 'x32', 'x64', 'x16att', 'x32att', 'x64att', 'x16nasm', 'x32nasm', 'x64nasm']:
        return b'\x90'
    elif arch in ['arm', 'armv8']:
        return b'\x00\xf0\x20\xe3'
    elif arch in ['armbe', 'armv8be']:
        return b'\xe3\x20\xf0\x00'
    elif arch in ['thumb', 'thumbv8']:
        return b'\x00\xbf'
    elif arch in ['thumbbe', 'thumbv8be']:
        return b'\xbf\x00'
    elif arch in ['arm64']:
        return b'\x1f\x20\x03\xd5'
    elif arch in ['hexagon']:
        return b'\x00\xc0\x00\x7f'
    elif arch in ['mips', 'mipsbe', 'mips64', 'mips64be']:
        return b'\x00\x00\x00\x00'
    elif arch in ['ppc64']:
        return b'\x00\x00\x00\x60'
    elif arch in ['ppc32be', 'ppc64be']:
        return b'\x60\x00\x00\x00'
    elif arch in ['sparc']:
        return b'\x00\x00\x00\x01'
    elif arch in ['sparcbe', 'sparc64be']:
        return b'\x01\x00\x00\x00'

    raise Exception('no NOP for architecture: %s' % arch)


binja_to_ks = {
    'aarch64': 'arm64',
    'armv7': 'arm',
    'armv7eb': 'armbe',
    'thumb2': 'thumb',
    'thumb2eb': 'thumbbe',
    'mipsel32': 'mips',
    'mips32': 'mipsbe',
    'ppc': 'ppc32be',
    'ppc_le': 'ERROR',
    'ppc64': 'ppc64be',
    'ppc64_le': 'ppc64',
    'sh4': 'ERROR',
    'x86_16': 'x16nasm',
    'x86': 'x32nasm',
    'x86_64': 'x64nasm'
}


def nopSelection(bv: BinaryView, start: int, size: int):
    nopByte = getNop(binja_to_ks[bv.arch.name])
    bv.write(start, nopByte * (size // len(nopByte)))
    print(
        f"[+]nop {(size // len(nopByte)) * len(nopByte)} bytes at 0x{start:x}\n{hex(start)}~{hex((size // len(nopByte)) * len(nopByte))}")



def uiPreProcess(bv: BinaryView):
    start = get_address_input("start_address", "start_address")
    end = get_address_input("end_address:if yourInput==startAddr,next you will input length", "end_address")
    # print(end)
    # print(type(end))
    if end != start:
        size = end - start
    else:
        size = get_int_input("length:int type", "length")
    return start, size


def uiConvert2EscapedString(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2EscapedString(bv, start, size)


def uiConvert2C_uint8_t(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2C_uint8_t(bv, start, size)


def uiConvert2C_uint16_t(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2C_uint16_t(bv, start, size)


def uiConvert2C_uint32_t(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2C_uint32_t(bv, start, size)


def uiConvert2C_uint64_t(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2C_uint64_t(bv, start, size)


def uiConvert2Puint8_t(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2Puint8_t(bv, start, size)


def uiConvert2Puint16_t(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2Puint16_t(bv, start, size)


def uiConvert2Puint32_t(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2Puint32_t(bv, start, size)


def uiConvert2Puint64_t(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2Puint64_t(bv, start, size)


def uiConvert2Pdouble(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2Pdouble(bv, start, size)


def uiConvert2Pfloat(bv: BinaryView):
    start, size = uiPreProcess(bv)
    convert2Pfloat(bv, start, size)


PluginCommand.register_for_range("Convert\\EscapedString", "", convert2EscapedString)
PluginCommand.register_for_range("Convert\\uint8_t(c)", "", convert2C_uint8_t)
PluginCommand.register_for_range("Convert\\uint16_t(c)", "", convert2C_uint16_t)
PluginCommand.register_for_range("Convert\\uint32_t(c)", "", convert2C_uint32_t)
PluginCommand.register_for_range("Convert\\uint64_t(c)", "", convert2C_uint64_t)
PluginCommand.register_for_range("Convert\\uint8_t(python)", "", convert2Puint8_t)
PluginCommand.register_for_range("Convert\\uint16_t(python)", "", convert2Puint16_t)
PluginCommand.register_for_range("Convert\\uint32_t(python)", "", convert2Puint32_t)
PluginCommand.register_for_range("Convert\\uint64_t(python)", "", convert2Puint64_t)
PluginCommand.register_for_range("Convert\\double(python)", "", convert2Pdouble)
PluginCommand.register_for_range("Convert\\float(python)", "", convert2Pfloat)
PluginCommand.register_for_range("Convert\\nop", "", nopSelection)

PluginCommand.register("UIConvert\\float(python)", "", uiConvert2Pfloat)
PluginCommand.register("UIConvert\\double(python)", "", uiConvert2Pdouble)
PluginCommand.register("UIConvert\\uint64_t(python)", "", uiConvert2Puint64_t)
PluginCommand.register("UIConvert\\uint32_t(python)", "", uiConvert2Puint32_t)
PluginCommand.register("UIConvert\\uint16_t(python)", "", uiConvert2Puint16_t)
PluginCommand.register("UIConvert\\uint8_t(python)", "", uiConvert2Puint8_t)
PluginCommand.register("UIConvert\\uint64_t(c)", "", uiConvert2C_uint64_t)
PluginCommand.register("UIConvert\\uint32_t(c)", "", uiConvert2C_uint32_t)
PluginCommand.register("UIConvert\\uint16_t(c)", "", uiConvert2C_uint16_t)
PluginCommand.register("UIConvert\\uint8_t(c)", "", uiConvert2C_uint8_t)
PluginCommand.register("UIConvert\\EscapedString", "", uiConvert2EscapedString)

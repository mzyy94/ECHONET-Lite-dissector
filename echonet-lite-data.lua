-- ########################################################
-- ECHONET Lite Wireshark dissector
-- ########################################################
--
--   Author : Yuki MIZUNO
--   Version: 0.0.1
--   License: MIT
--
-- ########################################################
--
--  Copyright (c) 2016 Yuki MIZUNO
--  This software is released under the MIT License.
--  http://opensource.org/licenses/MIT
--
local list = require("echonet-lite-codelist")

edata = Proto("echonetlite.edata", "ECHONET Lite Data (EDATA)")

-- ========================================================
-- ECHONET Lite Data fields definition.
-- ========================================================

edata.fields.seoj = ProtoField.uint24("echonetlite.edata.seoj", "Source ECHONET Lite object (SEOJ)", base.HEX)
edata.fields.seojgroup = ProtoField.uint8("echonetlite.edata.seoj.classgroup", "Class group code", base.HEX, list.group)
edata.fields.seojclass = ProtoField.uint8("echonetlite.edata.seoj.class", "Class code", base.HEX)
edata.fields.seojinstance = ProtoField.uint8("echonetlite.edata.seoj.instance", "Instance code", base.HEX)
edata.fields.deoj = ProtoField.uint24("echonetlite.edata.deoj", "Destination ECHONET Lite object (DEOJ)", base.HEX)
edata.fields.deojgroup = ProtoField.uint8("echonetlite.edata.deoj.classgroup", "Class group code", base.HEX, list.group)
edata.fields.deojclass = ProtoField.uint8("echonetlite.edata.deoj.class", "Class code", base.HEX)
edata.fields.deojinstance = ProtoField.uint8("echonetlite.edata.deoj.instance", "Instance code", base.HEX)
edata.fields.esv  = ProtoField.uint8("echonetlite.edata.esv", "ECHONET Lite service (ESV)",  base.HEX, list.esv)
edata.fields.opc  = ProtoField.uint8("echonetlite.edata.opc", "Property size (OPC)",  base.DEC)
edata.fields.property  = ProtoField.none("echonetlite.edata.property", "Property")
edata.fields.epc  = ProtoField.uint8("echonetlite.edata.epc", "ECHONET Property (EPC)",  base.HEX)
edata.fields.pdc  = ProtoField.uint8("echonetlite.edata.pdc", "Property Data Counter (PDC)",  base.DEC)
edata.fields.edt  = ProtoField.bytes("echonetlite.edata.edt",  "ECHONET Property Value Data (EDT)",  base.HEX)

-- ========================================================
-- Parse ECHONET Lite Data fields.
-- ========================================================

function edata.dissector(buffer, pinfo, tree)
    local data_len = buffer:len()

    local subtree = tree:add(edata, buffer(0, data_len))

    local sobj = "Unknown"
    if list.class[buffer(0,1):uint()] ~= nil and list.class[buffer(0,1):uint()][buffer(1,1):uint()] ~= nil then
        sobj = list.class[buffer(0,1):uint()][buffer(1,1):uint()]
    end

    local seojtree = subtree:add(edata.fields.seoj, buffer(0, 3))
    seojtree:append_text(string.format(" (%s)", sobj))
    seojtree:add(edata.fields.seojgroup, buffer(0, 1))
    seojtree:add(edata.fields.seojclass, buffer(1, 1), buffer(1,1):uint(), "Class code:", sobj, string.format("(0x%02x)", buffer(1,1):uint()))
    seojtree:add(edata.fields.seojinstance, buffer(2, 1))

    local dobj = "Unknown"
    if list.class[buffer(3,1):uint()] ~= nil and list.class[buffer(3,1):uint()][buffer(4,1):uint()] ~= nil then
        dobj = list.class[buffer(3,1):uint()][buffer(4,1):uint()]
    end

    local deojtree = subtree:add(edata.fields.deoj, buffer(3, 3))
    deojtree:append_text(string.format(" (%s)", dobj))
    deojtree:add(edata.fields.deojgroup, buffer(3, 1))
    deojtree:add(edata.fields.deojclass, buffer(4, 1), buffer(4,1):uint(), "Class code:", dobj, string.format("(0x%02x)", buffer(4,1):uint()))
    deojtree:add(edata.fields.deojinstance, buffer(5, 1))

    subtree:add(edata.fields.esv,  buffer(6, 1))
    subtree:add(edata.fields.opc,  buffer(7, 1))

    begin = 8
    for i=1,buffer(7, 1):uint() do
        local pdc = buffer(begin + 1, 1):uint()
        local proptree = subtree:add(edata.fields.property, buffer(begin, pdc + 2))
        proptree:append_text(string.format(" %d", i))
        proptree:add(edata.fields.epc, buffer(begin, 1))
        proptree:add(edata.fields.pdc, buffer(begin + 1, 1), pdc)
        if pdc > 0 then
            proptree:add(edata.fields.edt, buffer(begin + 2, pdc))
        end
        begin = begin + 2 + pdc
    end
end

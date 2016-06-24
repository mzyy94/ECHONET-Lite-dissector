-- ########################################################
-- ECHONET Lite Wireshark dissector
-- ########################################################
--
--   Author : Yuki MIZUNO
--   Version: 1.2.0
--   License: MIT
--
-- ########################################################
--
--  Copyright (c) 2016 Yuki MIZUNO
--  This software is released under the MIT License.
--  http://opensource.org/licenses/MIT
--

echonetlite = Proto("echonetlite", "ECHONET Lite")

-- ========================================================
-- ECHONET Lite Header value table
-- ========================================================

ehd1 = {
    [0x10] = "ECHONET Lite Protocol"
}

ehd2 = {
    [0x81] = "Format 1",
    [0x82] = "Format 2"
}

-- ========================================================
-- ECHONET Lite UDP payload fields definition.
-- ========================================================

echonetlite.fields.ehd  = ProtoField.protocol("echonetlite.ehd",  "ECHONET Lite Header (EHD)")
echonetlite.fields.ehd1 = ProtoField.uint8("echonetlite.ehd1",  "EHD1", base.HEX, ehd1)
echonetlite.fields.ehd2 = ProtoField.uint8("echonetlite.ehd2",  "EHD2", base.HEX, ehd2)
echonetlite.fields.tid  = ProtoField.uint16("echonetlite.tid",  "Transaction ID (TID)", base.HEX)
echonetlite.fields.reqin  = ProtoField.framenum("echonetlite.request_in", "Request In")
echonetlite.fields.resin  = ProtoField.framenum("echonetlite.response_in", "Response In")

-- ========================================================
-- Local state variable
-- ========================================================

reqlist = {}
reslist = {}

-- ========================================================
-- Parse ECHONET Lite UDP payload fields.
-- ========================================================

function echonetlite.dissector(buffer, pinfo, tree)
    local data_len = buffer:len()
    if data_len < 4 or buffer(0,1):uint() ~= 0x10 or (data_len < 12 and buffer(1,1):uint() == 0x81) then
        local data_dissector = Dissector.get("data")
        data_dissector:call(buffer(0):tvb(), pinfo, tree)
        do return end
    end

    pinfo.cols.protocol = "ECHONET Lite"
    pinfo.cols.info = ""

    local subtree = tree:add(echonetlite, buffer(0, data_len))
    local ehdtree = subtree:add(echonetlite.fields.ehd, buffer(0, 2))
    ehdtree:add(echonetlite.fields.ehd1, buffer(0, 1))
    ehdtree:add(echonetlite.fields.ehd2, buffer(1, 1))

    local tidtree = subtree:add(echonetlite.fields.tid, buffer(2, 2))
    local tid = buffer(2, 2):uint()
    local src, dst = tostring(pinfo.src), tostring(pinfo.dst)
    if reqlist[dst] == nil or reqlist[dst][tid] == nil then
        if not reqlist[src] then
            reqlist[src] = {}
        end
        reqlist[src][tid] = pinfo.number
        if reslist[dst] ~= nil and reslist[dst][tid] ~= nil then
            tidtree:add(echonetlite.fields.resin, buffer(2, 2), reslist[dst][tid])
        end
    else
        if not reslist[src] then
            reslist[src] = {}
        end
        reslist[src][tid] = pinfo.number
        tidtree:add(echonetlite.fields.reqin, buffer(2, 2), reqlist[dst][tid])
    end

    if buffer(1, 1):uint() == 0x81 then
        local edata_dissector = Dissector.get("echonetlite.edata")
        edata_dissector:call(buffer(4):tvb(), pinfo, subtree)
    else
        local data_dissector = Dissector.get("data")
        data_dissector:call(buffer(4):tvb(), pinfo, subtree)
    end
end

-- ========================================================
-- Register ECHONET Lite protocol to UDP port 3610
-- ========================================================

udp_table = DissectorTable.get("udp.port")
udp_table:add("3610", echonetlite)

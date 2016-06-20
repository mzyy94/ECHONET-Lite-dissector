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

local list = {}

-- ========================================================
-- ECHONET Lite code list
-- ========================================================

list.esv = {
    [0x60] = "SetI",
    [0x61] = "SetC",
    [0x62] = "Get",
    [0x63] = "INF_REQ",
    [0x6E] = "SetGet",
    [0x71] = "Set_Res",
    [0x72] = "Get_Res",
    [0x73] = "INF",
    [0x74] = "INFC",
    [0x7A] = "INFC_Res",
    [0x7E] = "SetGet_Res",
    [0x50] = "SetI_SNA",
    [0x51] = "SetC_SNA",
    [0x52] = "Get_SNA",
    [0x53] = "INF_SNA",
    [0x5E] = "SetGet_SNA"
}

list.group = {
    [0x00] = "Sensor-related device",
    [0x01] = "Air Conditioner-related device",
    [0x02] = "Housing/Facilities-related device",
    [0x03] = "Cooking/Household-related device",
    [0x04] = "Health-related device",
    [0x05] = "Management/Operation-related device",
    [0x06] = "Audiovisual-related device",
    [0x0E] = "Profile object"
}


return list

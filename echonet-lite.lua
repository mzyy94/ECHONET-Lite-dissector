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

echonetlite = Proto("echonet-lite", "ECHONET Lite")


-- ========================================================
-- Parse ECHONET Lite UDP payload fields.
-- ========================================================

function echonetlite.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "ECHONET Lite"
end

-- ========================================================
-- Register ECHONET Lite protocol to UDP port 3610
-- ========================================================

udp_table = DissectorTable.get("udp.port")
udp_table:add("3610", echonetlite)
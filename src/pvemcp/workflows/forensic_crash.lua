-- Forensic Crash Reporter
-- Triggered by pipeline failure events
local vmid = "9211" -- KP14-SUITE
local host = "192.168.1.252"
local log_path = "/tmp/pipeline_debug.log"

admin_notify("Pipeline failure detected on " .. vmid, "Forensic Path Initiated")
remote_log_capture(host, log_path, 30)
vm_etc_diff(vmid)
vm_ram_dump(vmid, "/tmp/crash_dump.bin")
return "Forensic package captured to /tmp/"

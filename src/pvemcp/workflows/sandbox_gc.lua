-- Ephemeral Sandbox Lifecycle
-- Cleanup routine for tmpl-* VMs
local templates = {"9000", "9100", "9101", "9102", "9103"}

for _, vmid in ipairs(templates) do
    admin_notify("Cleaning sandbox: " .. vmid, "Garbage Collection")
    vm_disk_reclaim(vmid)
    vm_state(vmid, "stop")
end
return "Sandbox cleanup complete"

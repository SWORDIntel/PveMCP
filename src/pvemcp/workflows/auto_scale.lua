-- Resource-Aware Auto-Scaling
local vms = {"100", "222", "9211"}

for _, vmid in ipairs(vms) do
    local metrics = vm_state(vmid, "status")
    -- In a real scenario, we would parse actual CPU/RAM from vm_metrics tool
    -- This is a placeholder for the logic
    if metrics.status == "running" then
        -- Logic to scale goes here
        -- e.g., if load > 90 then vm_config(vmid, "set", {"cores=8"})
        admin_notify("Checking scaling for " .. vmid, "Auto-Scale Routine")
    end
end
return "Scaling check complete"

-- Run Devin Pipeline
admin_notify("Starting Devin Desktop Analysis", "Devin Pipeline")
local res = vm_run_kp14_pipeline("9211", "/tmp/devin-desktop-next", "malware")
admin_notify("Devin Pipeline Result: " .. tostring(res.ok), "Devin Pipeline")
return "Analysis pipeline finished: " .. tostring(res.ok)

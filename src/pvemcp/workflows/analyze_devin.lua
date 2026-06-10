-- Automated Pipeline: Full Analysis of devin-desktop-next
local vmid = "9211"
local target = "/tmp/devin-desktop-next"
local output_dir = "/home/debian/kp14_output/devin_analysis"

admin_notify("Starting full analysis on Devin binary", "Pipeline Start")

-- 1. Create output directory
vm_guest_exec(vmid, "mkdir -p " .. output_dir)

-- 2. Run DIE (Detect-It-Easy)
vm_guest_exec(vmid, "/home/debian/DIE-engine/build/diec -j " .. target .. " > " .. output_dir .. "/die.json")

-- 3. Run peframe
vm_guest_exec(vmid, "/home/debian/peframe-venv/bin/peframe -j " .. target .. " > " .. output_dir .. "/peframe.json")

-- 4. Run capa (Capability Analysis)
vm_guest_exec(vmid, "/home/debian/capa-venv/bin/capa " .. target .. " > " .. output_dir .. "/capa.txt")

admin_notify("Full analysis pipeline complete.", "Pipeline Complete")
return "Analysis stored in " .. output_dir

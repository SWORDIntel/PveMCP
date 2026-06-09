import yaml

def generate_user_data(
    packages: list[str] | None = None,
    users: list[dict] | None = None,
    runcmd: list[str] | None = None,
    write_files: list[dict] | None = None,
) -> str:
    """Generate a cloud-init user-data YAML string."""
    data = {"#cloud-config": None} # Placeholder to ensure it's at the top
    
    if packages:
        data["packages"] = packages
    if users:
        data["users"] = users
    if runcmd:
        data["runcmd"] = runcmd
    if write_files:
        data["write_files"] = write_files
        
    yaml_str = yaml.dump(data, sort_keys=False)
    # Ensure #cloud-config is at the very top
    return "#cloud-config\n" + yaml_str.replace("#cloud-config: null\n", "")

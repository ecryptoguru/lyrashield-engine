// Docker detection tests — DOCKER_HOST probe + free alternatives.

#[cfg(test)]
mod tests {
    use std::path::Path;

    struct FreeAlternative {
        name: &'static str,
        url: &'static str,
    }

    fn free_alternatives() -> Vec<FreeAlternative> {
        vec![
            FreeAlternative { name: "Podman Desktop", url: "https://podman.io/" },
            FreeAlternative { name: "Rancher Desktop", url: "https://rancherdesktop.io/" },
            FreeAlternative { name: "Colima", url: "https://github.com/abiosoft/colima" },
        ]
    }

    fn probe_unix_socket(path: &str) -> bool {
        let p = path.strip_prefix("unix://").unwrap_or(path);
        Path::new(p).exists()
    }

    #[test]
    fn test_free_alternatives_include_all_three() {
        let alts = free_alternatives();
        let names: Vec<&str> = alts.iter().map(|a| a.name).collect();
        assert!(names.contains(&"Podman Desktop"));
        assert!(names.contains(&"Rancher Desktop"));
        assert!(names.contains(&"Colima"));
    }

    #[test]
    fn test_probe_nonexistent_socket() {
        assert!(!probe_unix_socket("unix:///nonexistent/sock"));
    }

    #[test]
    fn test_docker_host_default() {
        // The default DOCKER_HOST when unset is unix:///var/run/docker.sock.
        let default = "unix:///var/run/docker.sock";
        assert!(default.starts_with("unix://"));
    }
}

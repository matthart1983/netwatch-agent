/// Count established TCP connections from /proc/net/tcp and /proc/net/tcp6.
/// State 01 = ESTABLISHED in the hex-encoded state field.
#[cfg(target_os = "linux")]
pub fn count_established_connections() -> u32 {
    let count_file = |path: &str| -> u32 {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return 0;
        };
        contents
            .lines()
            .skip(1) // header
            .filter(|line| {
                line.split_whitespace()
                    .nth(3)
                    .map(|st| st == "01")
                    .unwrap_or(false)
            })
            .count() as u32
    };

    count_file("/proc/net/tcp") + count_file("/proc/net/tcp6")
}

#[cfg(target_os = "macos")]
pub fn count_established_connections() -> u32 {
    let output = std::process::Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output();
    let Ok(output) = output else { return 0 };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter(|l| l.contains("ESTABLISHED"))
        .count() as u32
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn count_established_connections() -> u32 {
    0
}

#[derive(Debug, Clone)]
pub struct TcpStates {
    pub established: u32,
    pub time_wait: u32,
    pub close_wait: u32,
}

#[cfg(target_os = "linux")]
pub fn collect_tcp_states() -> TcpStates {
    let count_states = |path: &str| -> (u32, u32, u32) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return (0, 0, 0);
        };
        let mut established = 0u32;
        let mut time_wait = 0u32;
        let mut close_wait = 0u32;
        for line in contents.lines().skip(1) {
            if let Some(st) = line.split_whitespace().nth(3) {
                match st {
                    "01" => established += 1,
                    "06" => time_wait += 1,
                    "08" => close_wait += 1,
                    _ => {}
                }
            }
        }
        (established, time_wait, close_wait)
    };

    let (e4, tw4, cw4) = count_states("/proc/net/tcp");
    let (e6, tw6, cw6) = count_states("/proc/net/tcp6");

    TcpStates {
        established: e4 + e6,
        time_wait: tw4 + tw6,
        close_wait: cw4 + cw6,
    }
}

#[cfg(target_os = "macos")]
pub fn collect_tcp_states() -> TcpStates {
    let output = std::process::Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output();
    let Ok(output) = output else {
        return TcpStates {
            established: 0,
            time_wait: 0,
            close_wait: 0,
        };
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut established = 0u32;
    let mut time_wait = 0u32;
    let mut close_wait = 0u32;
    for line in text.lines() {
        if line.contains("ESTABLISHED") {
            established += 1;
        } else if line.contains("TIME_WAIT") {
            time_wait += 1;
        } else if line.contains("CLOSE_WAIT") {
            close_wait += 1;
        }
    }
    TcpStates {
        established,
        time_wait,
        close_wait,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn collect_tcp_states() -> TcpStates {
    TcpStates {
        established: 0,
        time_wait: 0,
        close_wait: 0,
    }
}

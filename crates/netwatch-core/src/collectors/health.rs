use std::process::Command;

pub struct PingResult {
    pub rtt_ms: Option<f64>,
    pub loss_pct: f64,
}

pub fn run_ping(target: &str) -> PingResult {
    let output = match Command::new("ping")
        .args(["-c", "3", "-W", "1", target])
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            return PingResult {
                rtt_ms: None,
                loss_pct: 100.0,
            }
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    PingResult {
        rtt_ms: parse_avg_rtt(&text),
        loss_pct: parse_loss(&text),
    }
}

fn parse_loss(output: &str) -> f64 {
    for line in output.lines() {
        if line.contains("packet loss") || line.contains("% loss") {
            for part in line.split_whitespace() {
                if part.ends_with('%') {
                    if let Ok(val) = part.trim_end_matches('%').parse::<f64>() {
                        return val;
                    }
                }
            }
            for segment in line.split(',') {
                let trimmed = segment.trim();
                if trimmed.contains("% packet loss") || trimmed.contains("% loss") {
                    if let Some(pct_str) = trimmed.split('%').next() {
                        let pct_str = pct_str.trim();
                        if let Ok(val) = pct_str.parse::<f64>() {
                            return val;
                        }
                        if let Some(last_word) = pct_str.split_whitespace().last() {
                            let cleaned = last_word.trim_start_matches('(');
                            if let Ok(val) = cleaned.parse::<f64>() {
                                return val;
                            }
                        }
                    }
                }
            }
        }
    }
    100.0
}

fn parse_avg_rtt(output: &str) -> Option<f64> {
    for line in output.lines() {
        if line.contains("min/avg/max") || line.contains("rtt min/avg/max") {
            if let Some(stats) = line.split('=').nth(1) {
                let parts: Vec<&str> = stats.trim().split('/').collect();
                if parts.len() >= 2 {
                    return parts[1].trim().parse().ok();
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_loss_zero() {
        let output = "3 packets transmitted, 3 received, 0% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 0.0);
    }

    #[test]
    fn parse_loss_partial() {
        let output = "3 packets transmitted, 1 received, 66.7% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 66.7);
    }

    #[test]
    fn parse_loss_full() {
        let output = "3 packets transmitted, 0 received, 100% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 100.0);
    }

    #[test]
    fn parse_loss_empty() {
        assert_eq!(parse_loss(""), 100.0);
    }

    #[test]
    fn parse_avg_rtt_linux() {
        let output = "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.111 ms";
        assert_eq!(parse_avg_rtt(output), Some(0.456));
    }

    #[test]
    fn parse_avg_rtt_empty() {
        assert_eq!(parse_avg_rtt(""), None);
    }
}
